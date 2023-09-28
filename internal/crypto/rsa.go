package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
)

// We need to accept different algorithms
func EncryptOAEP(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, msg, nil)
}

func DecryptOAEP(priv *rsa.PrivateKey, msg []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, msg, nil)
}
