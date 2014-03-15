// Package jsonsig implements cryptographic signatures of JSON documents,
// using the algorithm described at
// https://github.com/couchbase/couchbase-lite-ios/wiki/Signed-Documents
//
// A signature is a JSON object that's typically stored within the object it signs, under a
// "(signed)" key, although it doesn't need to be.
package jsonsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"time"
)

// A parsed representation of a JSON signature.
// This type supports JSON marshaling and unmarshaling.
type Signature struct {
	PublicKey      rsa.PublicKey // The signer's public key
	Date           *time.Time    // Date/time signature was created (optional)
	Expiration     *time.Time    // Date/time signature expires (optional)
	messageDigest  []byte        // The digest of the message this is a signature of
	signatureBytes []byte        // The RSA signature data itself
}

// Generates a signature of a JSON-marshalable "message" object, using the given RSA private key.
// If includeDate is true, a timestamp will be added to the signature; if expiration is also
// nonzero, it will be included as the expiration interval, i.e. how long the signature remains
// valid after being signed.
//
// Making any changes to the message object will invalidate the signature, unless the changes are
// in ignored keys. Any underscore-prefixed key (except "_id") is ignored, as is "(signed)".
func CreateSignature(message map[string]interface{}, key *rsa.PrivateKey, includeDate bool, expiration time.Duration) (*Signature, error) {
	signature := Signature{
		PublicKey:     key.PublicKey,
		messageDigest: canonicalDigest(message),
	}
	if includeDate {
		now := time.Now()
		signature.Date = &now
		if expiration > 0 {
			expires := now.Add(expiration)
			signature.Expiration = &expires
		}
	}

	sigJson, err := json.Marshal(&signature)
	if err != nil {
		return nil, err
	}

	digest := sha1.Sum(sigJson)
	signature.signatureBytes, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, digest[:])
	if err != nil {
		return nil, err
	}
	return &signature, nil
}

// Signs the JSON-marshalable "message" object by calling CreateSignature, then embeds the
// signature within the object by adding it under a "(signed)" key.
//
// Making any changes to the message object will invalidate the signature, unless the changes are
// in ignored keys. Any underscore-prefixed key (except "_id") is ignored, as is "(signed)".
func AddSignature(message map[string]interface{}, key *rsa.PrivateKey, includeDate bool, expiration time.Duration) error {
	if sig, err := CreateSignature(message, key, includeDate, expiration); sig != nil {
		message["(signed)"] = sig
		return nil
	} else {
		return err
	}
}

func (s *Signature) MarshalJSON() ([]byte, error) {
	keyBytes, err := asn1.Marshal(s.PublicKey)
	if err != nil {
		return nil, err
	}
	sig := map[string]interface{}{
		"digest": []interface{}{"SHA1", base64.StdEncoding.EncodeToString(s.messageDigest)},
		"key":    []interface{}{"RSA", base64.StdEncoding.EncodeToString(keyBytes)},
	}
	if s.Date != nil {
		sig["date"] = s.Date.Format(time.RFC3339)
		if s.Expiration != nil {
			sig["expires"] = float64(s.Expiration.Sub(*s.Date) / time.Minute)
		}
	}
	if s.signatureBytes != nil {
		sig["sig"] = base64.StdEncoding.EncodeToString(s.signatureBytes)
	}
	return json.Marshal(sig)
}

// Computes the SHA-1 digest of a JSON object.
func canonicalDigest(jsonObject map[string]interface{}) []byte {
	edited := copyMap(jsonObject, func(key string) bool {
		return (len(key) == 0 || key == "_id" || key[0] != '_') && key != "(signed)"
	})
	// NOTE: json.Marshal appears to be compatible with our canonical-JSON format -- it emits
	// dictionary keys in sorted order and omits whitespace, at least. More testing is needed!
	canon, _ := json.Marshal(edited)
	digest := sha1.Sum(canon)
	return digest[:]
}

// Shallow-copies a map, copying only the keys for which the predicate returns true.
func copyMap(input map[string]interface{}, predicate func(key string) bool) map[string]interface{} {
	copied := map[string]interface{}{}
	for key, value := range input {
		if predicate(key) {
			copied[key] = value
		}
	}
	return copied
}
