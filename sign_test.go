package jsonsig

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"testing"
	"time"
)

func TestSign(t *testing.T) {
	bodyStr := `{
	   "_id": "person-0234B8F3A662F09BDE3DAE8E1A3F65CDB2256983",
	   "_rev": "3-9c44c92bdf74577db1df40a559c1f691",
	   "attachment_digests": {
	       "picture": "8s7zAEPrcZ9WBVD7nK8x4SA1DvY="
	   },
	   "first": "Jens",
	   "last": "Alfke",
	   "nick": "snej",
	   "parent_rev": "2-2d19e0d738823a560d67d27fa4b942ba",
	   "timestamp": "2014-02-23T23:54:27.917Z",
	   "type": "person",
	   "_attachments": {
	       "picture": {
	           "content_type": "image/jpeg",
	           "revpos": 3,
	           "digest": "md5-ck57Dy53Gd/ORfDiPkQHLg==",
	           "length": 39730,
	           "stub": true
	       }
	   }
	}`
	var body map[string]interface{}
	json.Unmarshal([]byte(bodyStr), &body)

	key, _ := rsa.GenerateKey(rand.Reader, 1024)

	sigStruct, err := CreateSignature(body, key, true, time.Hour)
	if err != nil {
		t.Fatalf("CreateSignature failed: %v", err)
	}

	sigBytes, _ := json.Marshal(sigStruct)
	log.Printf("Signature JSON = %s", sigBytes)

	var sigParsed map[string]interface{}
	json.Unmarshal(sigBytes, &sigParsed)
	signature, err := ParseSignature(sigParsed)
	log.Printf("Signature struct = %+v", signature)
	if signature == nil {
		t.Fatalf("ParseSignature failed: %v", err)
	}
	if !signature.StillValid() {
		t.Fatalf("StillValid failed")
	}

	if !signature.VerifyMessage(body) {
		t.Fatalf("VerifyMessage failed")
	}

}
