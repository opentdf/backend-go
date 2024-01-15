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
	PublicKeyRsa  rsa.PublicKey `json:"publicKey"`
	PublicKeyEc   ecdsa.PublicKey
	Certificate   x509.Certificate `json:"certificate"`
	CertificateEc x509.Certificate `json:"certificateEc"`
	Attributes    []Attribute      `json:"attributes"`
	Session       p11.Pkcs11Session
	OIDCVerifier  *oidc.IDTokenVerifier
}
