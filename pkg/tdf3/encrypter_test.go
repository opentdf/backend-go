package tdf3

import (
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"
)

func TestEncryptWithPublicKeyFailure(t *testing.T) {
	// Small size of PublicKey
	mockKey := &rsa.PublicKey{
		N: big.NewInt(123),
		E: 2048,
	}

	var i interface{}
	i = mockKey

	t.Log(mockKey.Size())

	output, err := EncryptWithPublicKey([]byte{}, &i)

	t.Log(output)

	if err == nil {
		t.Errorf("Expected  error, but got: %v", err)
	}
}

func TestError(t *testing.T) {
	expectedResult := "hsm decrypt error"
	output := Error.Error(ErrHsmEncrypt)

	if reflect.TypeOf(output).String() != "string" {
		t.Error("Expected string")
	}

	if output != expectedResult {
		t.Errorf("Output %v not equal to expected %v", output, expectedResult)
	}
}
