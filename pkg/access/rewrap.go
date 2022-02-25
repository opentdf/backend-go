package access

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"strings"

	"github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
	"github.com/opentdf/backend-go/pkg/nano"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/square/go-jose.v2/jwt"
)

// RewrapRequest HTTP request body in JSON
type RewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"`
}

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Entity          Entity         `json:"entity"`
	Policy          string         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
}

type Entity struct {
	Id         string
	Aliases    []string
	Attributes []Attribute
	PublicKey  []byte
}

type RewrapResponse struct {
	EntityWrappedKey []byte `json:"entityWrappedKey"`
	SessionPublicKey string `json:"sessionPublicKey"`
	SchemaVersion    string `json:"schemaVersion,omitempty"`
}

type customClaims struct {
	RequestBody string `json:"requestBody,omitempty"`
}

// Handler decrypts and encrypts the symmetric data key
func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	log.Printf("headers %s", r.Header)
	log.Printf("body %s", r.Body)
	log.Printf("ContentLength %d", r.ContentLength)
	// preflight
	if r.ContentLength == 0 {
		return
	}
	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err := decoder.Decode(&rewrapRequest)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	requestToken, err := jwt.ParseSigned(rewrapRequest.SignedRequestToken)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	c := &jwt.Claims{}
	c2 := &customClaims{}
	err = requestToken.UnsafeClaimsWithoutVerification(c, c2)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	log.Println(c2.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(c2.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	log.Println(requestBody.ClientPublicKey)
	// TODO get OIDC public key
	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		// FIXME handle error
		log.Panic("err missing clientPublicKey")
		return
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	log.Println(clientPublicKey)
	// nano header
	log.Println(requestBody.KeyAccess.Header)
	log.Println(len(requestBody.KeyAccess.Header))
	s := kaitai.NewStream(bytes.NewReader(requestBody.KeyAccess.Header))
	n := nano.NewNanotdf()
	err = n.Read(s, n, n)
	if err != nil {
		log.Panic(err)
	}
	log.Print(n.Header.Length)
	//// unwrap
	//symmetricKey, err := tdf3.DecryptWithPrivateKey(rewrapRequest.KeyAccess.WrappedKey, &p.PrivateKey)
	//if err != nil {
	//	// FIXME handle error
	//	log.Panic(err)
	//	return
	//}
	//// rewrap
	//rewrappedKey, err := tdf3.EncryptWithRSAPublicKey(symmetricKey, entityPublicKey)
	//if err != nil {
	//	// FIXME handle error
	//	log.Panic(err)
	//	return
	//}
	// TODO validate policy
	log.Println()
	// TODO store policy
	rewrappedKey := []byte("TODO")
	responseBytes, err := json.Marshal(&RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(responseBytes)
}
