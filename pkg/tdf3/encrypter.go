package tdf3

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"io"
)

// EncryptWithRSAPublicKey encrypts data with public key
func EncryptWithRSAPublicKey(msg []byte, publicKey *rsa.PublicKey) (ciphertext []byte, err error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, msg, nil)
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *crypto.PublicKey) (ciphertext []byte, err error) {
	publicKey, _ := (*pub).(*rsa.PublicKey)
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, msg, nil)
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(msg []byte, private *crypto.PrivateKey) (cleartext []byte, err error) {
	privateKey, _ := (*private).(*rsa.PrivateKey)
	return rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, msg, nil)
}

func NewCipher(key []byte) (Block, error) {
	block := Block{
		Streamable: false,
		keyLength:  len(key),
	}
	switch block.keyLength {
	case 16:
		block.Algorithm = "AES-128-CBC"
	case 24:
		block.Algorithm = "AES-192-CBC"
	case 32:
		block.Algorithm = "AES-256-CBC"
	}
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return block, err
	}
	block.Block = aesBlock
	block.IV = make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, block.IV)
	if err != nil {
		return block, err
	}
	return block, nil
}

func NewGCM(block Block) (cipher.AEAD, error) {
	// FIXME implement tdf3.AEAD
	block.Streamable = true
	switch block.keyLength {
	case 16:
		block.Algorithm = "AES-128-GCM"
	case 24:
		block.Algorithm = "AES-192-GCM"
	case 32:
		block.Algorithm = "AES-256-GCM"
	}
	aesGCM, err := cipher.NewGCM(block.Block)
	if err != nil {
		return aesGCM, err
	}
	return aesGCM, nil
}

func NewStreamCipher(key []byte) (cipher.Stream, error) {
	// FIXME implement
	return nil, nil
}
