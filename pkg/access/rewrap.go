package access

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/opentdf/backend-go/pkg/tdf3"
)

// RewrapRequest HTTP request body in JSON
type RewrapRequest struct {
	AuthToken     string         `json:"authToken"`
	KeyAccess     tdf3.KeyAccess `json:"keyAccess"`
	Entity        Entity         `json:"entity"`
	Policy        string         `json:"policy,omitempty"`
	Algorithm     string         `json:"algorithm,omitempty"`
	SchemaVersion string         `json:"schemaVersion,omitempty"`
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

// Handler decrypts and encrypts the symmetric data key
func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	log.Print(r.Body)
	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err := decoder.Decode(&rewrapRequest)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// TODO get OIDC public key
	// Decode PEM entity public key
	block, _ := pem.Decode(rewrapRequest.Entity.PublicKey)
	if block == nil {
		// FIXME handle error
		log.Panic("err missing entity public key")
		return
	}
	entityPublicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// unwrap
	symmetricKey, err := tdf3.DecryptWithPrivateKey(rewrapRequest.KeyAccess.WrappedKey, &p.PrivateKey)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// rewrap
	rewrappedKey, err := tdf3.EncryptWithRSAPublicKey(symmetricKey, entityPublicKey)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// TODO validate policy
	log.Println()
	// TODO store policy
	responseBytes, err := json.Marshal(&RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(responseBytes)
}
