package access

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
)

type Provider struct {
	URI          url.URL           `json:"uri"`
	PrivateKey   crypto.PrivateKey `json:"-"`
	PublicKeyRsa rsa.PublicKey     `json:"publicKey"`
	PublicKeyEc  ecdsa.PublicKey
	Certificate  x509.Certificate `json:"certificate"`
	Attributes   []Attribute      `json:"attributes"`
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
