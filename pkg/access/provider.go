package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/opentdf/backend-go/pkg/p11"
)

type Provider struct {
	URI           url.URL `json:"uri"`
	PrivateKey    p11.Pkcs11PrivateKeyRSA
	PublicKeyRSA  rsa.PublicKey `json:"publicKey"`
	PublicKeyEC   ecdsa.PublicKey
	Certificate   x509.Certificate `json:"certificate"`
	CertificateEC x509.Certificate `json:"certificateEc"`
	Attributes    []Attribute      `json:"attributes"`
	Session       p11.Pkcs11Session
	OIDCVerifier  *oidc.IDTokenVerifier
}
