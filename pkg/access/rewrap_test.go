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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestLegacyBearerTokenFails(t *testing.T) {
	var tests = []struct {
		name     string
		metadata []string
		msg      string
	}{
		// the table itself
		{"no auth header", []string{}, "no auth token"},
		{"multiple auth", []string{"Authorization", "a", "Authorization", "b"}, "auth fail"},
		{"no bearer", []string{"Authorization", "a"}, "auth fail"},
		{"no token", []string{"Authorization", "Bearer "}, "auth fail"},
	}
	// The execution loop
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(tt.metadata...))
			p, err := legacyBearerToken(ctx, "")
			if p != "" || err == nil || !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("should fail p=[%s], err=[%s], expected [%s]", p, err, tt.msg)
			}
		})
	}
}

func TestLegacyBearerTokenEtc(t *testing.T) {
	p, err := legacyBearerToken(context.Background(), "")
	if p != "" || err == nil || !strings.Contains(err.Error(), "no auth token") {
		t.Errorf("should fail p=[%s], err=[%s], expected 'no auth token'", p, err)
	}

	p, err = legacyBearerToken(context.Background(), "something")
	if p != "something" || err != nil {
		t.Errorf("should succeed p=[%s], err=[%s], expected 'something' in p", p, err)
	}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("Authorization", "Bearer TOKEN"))
	p, err = legacyBearerToken(ctx, "")
	if p != "TOKEN" || err != nil {
		t.Errorf("should succeed p=[%s], err=[%s], expected p='TOKEN'", p, err)
	}
}

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
	if !ok || status.Code() != codes.Unauthenticated {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
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
	if !ok || status.Code() != codes.PermissionDenied {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
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
	if !ok || status.Code() != codes.PermissionDenied {
		t.Errorf("got [%s], but should return expected error, status.message: [%s], status.code: [%s]", err, status.Message(), status.Code())
	}
}
