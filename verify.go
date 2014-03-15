package jsonsig

import (
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"time"
)

var NoSignatureErr = errors.New("Missing structure")
var StructureErr = errors.New("Invalid signature structure")
var VerifyErr = errors.New("Self-signature is invalid")
var TimeErr = errors.New("Invalid timestamps")

// Gets the signature of an already-parsed signed JSON object.
// The signature must be in the "(signed)" property.
func GetSignature(body map[string]interface{}) (*Signature, error) {
	return ParseSignature(body["(signed)"])
}

// Reads a JSON signature from its already-parsed JSON form, i.e. an object containing keys like
// "key", "digest", "sig"...
// It is _not_ an error if the signature has expired. You can check for this condition by calling
// the signature's StillValid method.
func ParseSignature(input interface{}) (*Signature, error) {
	if input == nil {
		return nil, NoSignatureErr
	}
	sigProp, _ := input.(map[string]interface{})
	if sigProp == nil {
		return nil, StructureErr
	}
	keyBytes := getTypedData(sigProp["key"], "RSA")
	if keyBytes == nil {
		return nil, StructureErr
	}
	var signature Signature
	if _, err := asn1.Unmarshal(keyBytes, &signature.PublicKey); err != nil {
		return nil, StructureErr
	}
	signature.messageDigest = getTypedData(sigProp["digest"], "SHA1")
	if signature.messageDigest == nil {
		return nil, StructureErr
	}
	var err error
	signature.signatureBytes, err = base64.StdEncoding.DecodeString(sigProp["sig"].(string))
	if err != nil {
		return nil, StructureErr
	}

	unsigned := copyMap(sigProp, func(key string) bool { return key != "sig" })
	sigDigest := canonicalDigest(unsigned)
	err = rsa.VerifyPKCS1v15(&signature.PublicKey, crypto.SHA1, sigDigest, signature.signatureBytes)
	if err != nil {
		return nil, VerifyErr
	}

	// Parse and check the date and expiration:
	if dateStr, ok := sigProp["date"].(string); ok {
		date, err := time.Parse(time.RFC3339Nano, dateStr)
		if err != nil {
			return nil, TimeErr
		}
		signature.Date = &date
		if time.Since(date) < -time.Second {
			return nil, TimeErr // timestamp is in the future!
		}
		if expiresIn, ok := sigProp["expires"].(float64); ok {
			if expiresIn < 0 {
				return nil, TimeErr
			}
			expiration := signature.Date.Add(time.Duration(expiresIn) * time.Minute)
			signature.Expiration = &expiration
		}
	}
	return &signature, nil
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	sig, err := ParseSignature(obj)
	if err != nil {
		return err
	}
	*s = *sig
	return nil
}

// Returns false if the signature has expired (or is nil.)
func (s *Signature) StillValid() bool {
	return s != nil && (s.Expiration == nil || time.Since(*s.Expiration) < 0)
}

// Verifies that a signature actually applies to the JSON object.
// If the signature is valid but this method returns false, it means the message given does not
// match what was originally signed.
func (s *Signature) VerifyMessage(message map[string]interface{}) bool {
	return s.StillValid() && reflect.DeepEqual(s.messageDigest, canonicalDigest(message))
}

// Parses value as a 2-element array whose first element must be requiredType and whose second
// must be a base64 string. Returns the decoded data.
func getTypedData(value interface{}, requiredType string) []byte {
	array, ok := value.([]interface{})
	if !ok || len(array) < 2 {
		log.Fatalf("error: %T", value)
		return nil
	}
	if actualType, _ := array[0].(string); actualType != requiredType {
		return nil
	}
	encoded, ok := array[1].(string)
	if !ok {
		return nil
	}
	bytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	return bytes
}
