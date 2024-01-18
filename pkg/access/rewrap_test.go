package access

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"strings"
	"testing"

	"github.com/opentdf/backend-go/pkg/p11"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestHandlerAuthFailure0(t *testing.T) {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRSA: rsa.PublicKey{},
		PublicKeyEC:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},

		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	body := `{"mock": "value"}`
	_, err := kas.Rewrap(context.Background(), &RewrapRequest{SignedRequestToken: body})
	status, ok := status.FromError(err)
	if !ok || strings.Compare(status.Message(), "forbidden") != 0 {
		t.Errorf("got [%s], but should return expected error, status.message: [%s]", err, status.Message())
	}
}

func TestHandlerAuthFailure1(t *testing.T) {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRSA: rsa.PublicKey{},
		PublicKeyEC:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},

		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	body := `{"mock": "value"}`
	md := map[string][]string{
		"Authorization": {"Bearer invalidToken"},
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	_, err := kas.Rewrap(ctx, &RewrapRequest{SignedRequestToken: body})
	status, ok := status.FromError(err)
	if !ok || strings.Compare(status.Message(), "forbidden") != 0 {
		t.Errorf("got [%s], but should return expected error, status.message: [%s]", err, status.Message())
	}
}

func TestHandlerAuthFailure2(t *testing.T) {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRSA: rsa.PublicKey{},
		PublicKeyEC:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},

		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	body := `{"mock": "value"}`
	_, err := kas.Rewrap(context.Background(), &RewrapRequest{SignedRequestToken: body, Bearer: "invalidToken"})
	status, ok := status.FromError(err)
	if !ok || strings.Compare(status.Message(), "forbidden") != 0 {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], ok: [%t]", err, status.Message(), ok)
	}
}
