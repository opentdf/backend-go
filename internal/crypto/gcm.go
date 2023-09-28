package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

type GCM struct {
	alg    CryptoAlgorithm
	key    []byte
	cipher cipher.AEAD
}

func newGCM(alg CryptoAlgorithm) (*GCM, error) {
	// Divide key length by 8 to get the number of bytes
	keyLength, err := alg.BlockSize()
	if err != nil {
		return nil, err
	}
	key, err := generateKey(keyLength / 8)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &GCM{
		alg:    alg,
		key:    key,
		cipher: cipher,
	}, nil
}

func newGCMWithKey(alg CryptoAlgorithm, key []byte) (*GCM, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &GCM{
		alg:    alg,
		key:    key,
		cipher: cipher,
	}, nil
}

func (g *GCM) Algorithm() string {
	return g.alg.String()
}

func (g *GCM) Key() []byte {
	return g.key
}

func (g *GCM) EncryptedSegmentSizeDefault(size int) int {
	// A total encrypted segment for gcm would be segment size + nonce size + auth tag size
	return size + g.cipher.NonceSize() + 16
}

func (g *GCM) Encrypt(msg []byte) ([]byte, error) {
	nonce, err := generateNonce(g.cipher.NonceSize())
	if err != nil {
		return nil, err
	}
	cipherText := g.cipher.Seal(nonce, nonce, msg, nil)
	return cipherText, nil
}

func (g *GCM) Decrypt(msg []byte) ([]byte, error) {
	nonce, cipherText := msg[:g.cipher.NonceSize()], msg[g.cipher.NonceSize():]
	plainText, err := g.cipher.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
