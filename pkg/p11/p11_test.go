package p11

import (
	"crypto"
	"github.com/miekg/pkcs11"
	"reflect"
	"testing"
)

func TestNewSession(t *testing.T) {
	ctx := &pkcs11.Ctx{}
	handle := pkcs11.SessionHandle(1)

	session := NewSession(ctx, handle)

	if session.ctx != ctx {
		t.Errorf("Expected context to be %v, but got %v", ctx, session.ctx)
	}

	if session.handle != handle {
		t.Errorf("Expected handle to be %v, but got %v", handle, session.handle)
	}
}

func TestNewPrivateKeyRSA(t *testing.T) {
	handle := pkcs11.ObjectHandle(2)

	privateKey := NewPrivateKeyRSA(handle)

	if privateKey.handle != handle {
		t.Errorf("Expected handle to be %v, but got %v", handle, privateKey.handle)
	}
}

func TestHashToPKCS11Success(t *testing.T) {
	testCases := []struct {
		inputHash     crypto.Hash
		expectedHash  uint
		expectedMGF   uint
		expectedLen   uint
		expectedError error
	}{
		{crypto.SHA1, pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil},
		{crypto.SHA224, pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil},
		{crypto.SHA256, pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil},
		{crypto.SHA384, pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil},
		{crypto.SHA512, pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil},
		{crypto.SHA3_256, 0, 0, 0, ErrUnsupportedRSAOptions},
	}

	for _, tc := range testCases {
		hashAlg, mgfAlg, hashLen, err := hashToPKCS11(tc.inputHash)

		if hashAlg != tc.expectedHash || mgfAlg != tc.expectedMGF || hashLen != tc.expectedLen || err != tc.expectedError {
			t.Errorf("For input %v, expected (%v, %v, %v, %v), but got (%v, %v, %v, %v)", tc.inputHash, tc.expectedHash, tc.expectedMGF, tc.expectedLen, tc.expectedError, hashAlg, mgfAlg, hashLen, err)
		}
	}
}

func TestDecryptOAEP(t *testing.T) {
	handle1 := pkcs11.ObjectHandle(2)
	privateKey := NewPrivateKeyRSA(handle1)

	ctx := &pkcs11.Ctx{}
	handle := pkcs11.SessionHandle(1)

	session := NewSession(ctx, handle)

	ciphertext := []byte("YourCiphertextDataHere")
	label := []byte("YourLabelDataHere")

	decrypted, err := DecryptOAEP(&session, &privateKey, ciphertext, crypto.SHA256, label)

	t.Log(decrypted)

	if err != nil {
		t.Errorf("Error: %v", err)
	}
}

func TestError(t *testing.T) {
	expectedResult := "hsm decrypt error"
	output := Error.Error(ErrHsmDecrypt)

	if reflect.TypeOf(output).String() != "string" {
		t.Error("Expected string")
	}

	if output != expectedResult {
		t.Errorf("Output %v not equal to expected %v", output, expectedResult)
	}
}
