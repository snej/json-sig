package jsonsig

import (
	"encoding/json"
	"log"
	"testing"
)

func TestVerify(t *testing.T) {
	bodyStr := `{
	   "_id": "person-0234B8F3A662F09BDE3DAE8E1A3F65CDB2256983",
	   "_rev": "3-9c44c92bdf74577db1df40a559c1f691",
	   "(signed)": {
	       "digest": [
	           "SHA1",
	           "Z2VZ4k0DwugzttY5nE6uz6EG5mM="
	       ],
	       "key": [
	           "RSA",
	           "MIIBCgKCAQEAyZhczZbrILPFqoDnBKgJD9NE1ZDJru8KBlrrCM69lxkJQn6njhhnAswyqtIPksmaxMPhwyfadqiK4KsDG1QYIYVd2c4GW6OFq5OnFfXvGD8V/M9Q9hzwqu4uRGb+RUPMnq35mgLJAvVR7yBsLm6TVOdtQ6KHX3Vsu6b4dbMSjH/tVUBEqdj3nWR93fxSFsMKAmsEEZWruQyS4Sl7SrYUz+7w0ddNiBxd1EiYRDKW9cXkSxN0Vo9NSMoV2md4xLTxgLpYOqJeiSjoOjaHpn5pyV1z8xBq3lKlPM6kuQt/edaP0c+5RvrPBTI4OZvaQPfuRUKa7pbYeXoyoId1UpYQ2QIDAQAB"
	       ],
	       "sig": "FUDG2Hd3rMxiLL9zeJcCPMPBHlKs6t9g1krqv/fHZ9P7XUnzswg0x0ePrZe44tpH1MdG/ITowZrrDrov/vaDypl6avGKCdmvu1c3oS1EjxZbUEuG7PAWojFrBkE3u00Jzmm0mM0FFBKKeFoz3Zq0JJqW5z/QZLmqU7n13Nqj5pQ/dgsJfoS97Tdo8HMJSEHfXTQc/HLR4IiIkyiLp6UEJFHkZRBvfE+PgHj45g+LaZuhJ2VEETxYW7UQnu6JbzOc1KfNv569f6Umam8wXxyfEGeJYa9ffRTt35i/gxQns+g9WeA68x/oIEfBy8GmPOZtGLXu3oGVjgryk9bsW0xudw=="
	   },
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

	signature, err := GetSignature(body)
	if signature == nil {
		t.Fatalf("Invalid document signature: %v", err)
	}
	if !signature.StillValid() {
		log.Fatalf("Signature has expired")
	}
	log.Printf("Signature date = %v", signature.Date)
	log.Printf("Signature expiration = %v", signature.Expiration)
	log.Printf("Signature = %+v", signature)
	log.Printf("Signature's message digest = %x", signature.MessageDigest)
	log.Printf("Actual message digest      = %x", canonicalDigest(body))

	if !signature.VerifyMessage(body) {
		t.Fatalf("Document doesn't match signature")
	}
	log.Printf("*** OK! ***")
}
