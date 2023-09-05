package tdf3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
)

const (
	ErrHsmEncrypt    = Error("hsm encrypt error")
	ErrPublicKeyType = Error("public key wrong type")
)

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *interface{}) ([]byte, error) {
	publicKey, ok := (*pub).(*rsa.PublicKey)
	if !ok {
		return nil, ErrPublicKeyType
	}
	// TODO add why SHA1 here is acceptable
	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, msg, nil)
	if err != nil {
		return nil, errors.Join(ErrHsmEncrypt, err)
	}
	return bytes, nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
