package access

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
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

func TestExportRsaPublicKeyAsPemStr(t *testing.T) {
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

func TestExportEcPublicKeyAsPemStr(t *testing.T) {
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
