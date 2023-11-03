package access

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"testing"
)

// MockRSAPublicKey is a mock implementation of the rsa.PublicKey interface for testing.
type MockRSAPublicKey struct {
	N *big.Int
	E int
}

func (mockKey *MockRSAPublicKey) Public() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: mockKey.N,
		E: mockKey.E,
	}
}

func TestExportRsaPublicKeyAsPemStrSuccess(t *testing.T) {
	mockKey := &MockRSAPublicKey{
		N: big.NewInt(123),
		E: 65537,
	}

	output, err := exportRsaPublicKeyAsPemStr(mockKey.Public())

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if len(output) == 0 {
		t.Error("Expected not empty string")
	}

	if reflect.TypeOf(output).String() != "string" {
		t.Errorf("Output %v not equal to expected %v", reflect.TypeOf(output).String(), "string")
	}
}

func TestExportEcPublicKeyAsPemStrSuccess(t *testing.T) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Errorf("Failed to generate a private key: %v", err)
	}
	output, err := exportEcPublicKeyAsPemStr(&privateKey.PublicKey)

	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	if len(output) == 0 {
		t.Error("Expected not empty string")
	}

	if reflect.TypeOf(output).String() != "string" {
		t.Errorf("Output %v not equal to expected %v", reflect.TypeOf(output).String(), "string")
	}
}

func TestExportCertificateAsPemStrSuccess(t *testing.T) {
	certBytes, err := os.ReadFile("./testdata/cert.der")
	if err != nil {
		t.Errorf("Failed to read certificate file in test: %v", err)
	}

	mockCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Errorf("Failed to parse certificate in test: %v", err)
	}

	pemStr, err := exportCertificateAsPemStr(mockCert)
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}

	// Decode the pemStr back into a block
	pemBlock, _ := pem.Decode([]byte(pemStr))
	if pemBlock == nil {
		t.Error("Failed to decode PEM block from the generated string")
	}

	// Ensure that the PEM block has the expected type "CERTIFICATE"
	if pemBlock.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM block type to be 'CERTIFICATE', but got '%s'", pemBlock.Type)
	}

	// Compare the decoded certificate bytes with the original mock certificate bytes
	if !bytes.Equal(pemBlock.Bytes, certBytes) {
		t.Error("Certificate bytes mismatch")
	}
}

func TestExportCertificateAsPemStrFailure(t *testing.T) {

}

func TestError(t *testing.T) {
	expectedResult := "certificate encode error"
	output := Error.Error(ErrCertificateEncode)

	if reflect.TypeOf(output).String() != "string" {
		t.Error("Expected string")
	}

	if output != expectedResult {
		t.Errorf("Output %v not equal to expected %v", output, expectedResult)
	}
}
