package tdf3

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
)

const (
	ErrHsmEncrypt = Error("hsm decrypt error")
)

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *interface{}) ([]byte, error) {
	publicKey, _ := (*pub).(*rsa.PublicKey)
	bytes, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, publicKey, msg, nil)
	return bytes, errors.Join(ErrHsmEncrypt, err)
}

type Error string

func (e Error) Error() string {
	return string(e)
}
