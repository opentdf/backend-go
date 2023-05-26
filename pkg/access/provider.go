package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/opentdf/backend-go/pkg/p11"
	// "golang.org/x/oauth2"
)

type Provider struct {
	URI          url.URL `json:"uri"`
	PrivateKey   p11.Pkcs11PrivateKeyRSA
	PublicKeyRsa rsa.PublicKey `json:"publicKey"`
	PublicKeyEc  ecdsa.PublicKey
	Certificate  x509.Certificate `json:"certificate"`
	Attributes   []Attribute      `json:"attributes"`
	Session      p11.Pkcs11Session
	OIDCVerifier *oidc.IDTokenVerifier
}

// NewProvider errors if untrusted
func NewProvider(uri url.URL) (*Provider, error) {
	// TODO check trustStore
	return &Provider{
		URI: uri,
	}, nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	err := encoder.Encode(p)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
}
