package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"log/slog"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/opentdf/backend-go/pkg/p11"
)

type Provider struct {
	URI          url.URL `json:"uri"`
	PrivateKey   p11.Pkcs11PrivateKeyRSA
	PublicKeyRsa rsa.PublicKey `json:"publicKey"`
	PublicKeyEc  ecdsa.PublicKey
	Certificate  x509.Certificate `json:"certificate"`
	Attributes   []Attribute      `json:"attributes"`
	Logger       *slog.Logger
	Session      p11.Pkcs11Session
	OIDCVerifier *oidc.IDTokenVerifier
}
