package access

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"github.com/opentdf/backend-go/pkg/p11"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHandlerEmptyRequestFailure(t *testing.T) {
	request, _ := http.NewRequest(http.MethodGet, "/v2/rewrap", nil)
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRsa: rsa.PublicKey{},
		PublicKeyEc:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Attributes:   nil,
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	kas.Handler(response, request)
	result := response.Result().Status

	if strings.Compare(result, "400 Bad Request") != 0 {
		t.Errorf("got %s, but should return error", result)
	}
}

func TestHandlerAuthFailure0(t *testing.T) {
	body := `{"mock": "value"}`
	request, _ := http.NewRequest(http.MethodGet, "/v2/rewrap", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")

	response := httptest.NewRecorder()

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRsa: rsa.PublicKey{},
		PublicKeyEc:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Attributes:   nil,
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	kas.Handler(response, request)
	result := response.Result().Status

	if strings.Compare(result, "401 Unauthorized") != 0 {
		t.Errorf("got %s, but should return error", result)
	}
}

func TestHandlerAuthFailure1(t *testing.T) {
	body := `{"mock": "value"}`
	request, _ := http.NewRequest(http.MethodGet, "/v2/rewrap", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer invalidToken")

	response := httptest.NewRecorder()

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRsa: rsa.PublicKey{},
		PublicKeyEc:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Attributes:   nil,
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	kas.Handler(response, request)

	resultStatus := response.Result().Status

	if strings.Compare(resultStatus, "400 Bad Request") != 0 {
		t.Errorf("got %s, but should return error", resultStatus)
	}
}

func TestHandlerAuthFailure2(t *testing.T) {
	body := `{"mock": "value"}`
	request, _ := http.NewRequest(http.MethodGet, "/v2/rewrap", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "invalidToken")

	response := httptest.NewRecorder()

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRsa: rsa.PublicKey{},
		PublicKeyEc:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Attributes:   nil,
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	kas.Handler(response, request)

	resultStatus := response.Result().Status

	if strings.Compare(resultStatus, "400 Bad Request") != 0 {
		t.Errorf("got %s, but should return error", resultStatus)
	}
}
