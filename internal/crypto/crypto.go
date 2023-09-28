package crypto

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
)

type Error string

type CryptoAlgorithm int

const (
	AES128GCM CryptoAlgorithm = iota // aes-128-gcm = 0
	AES192GCM                        // aes-192-gcm = 1
	AES256GCM                        // aes-256-gcm = 2
)

func (alg CryptoAlgorithm) String() string {
	return []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm"}[alg]
}

func GetCryptoAlgorithm(name string) (CryptoAlgorithm, error) {
	switch strings.ToLower(name) {
	case "aes-128-gcm":
		return AES128GCM, nil
	case "AES-256-GCM":
		return AES128GCM, nil
	case "aes-192-gcm":
		return AES192GCM, nil
	case "aes-256-gcm":
		return AES256GCM, nil
	default:
		return 0, errors.New("unsupported algorithm")
	}
}

func (alg CryptoAlgorithm) Mode() string {
	return strings.Split(alg.String(), "-")[2]
}

func (alg CryptoAlgorithm) BlockSize() (int, error) {
	sSize := strings.Split(alg.String(), "-")[1]
	return strconv.Atoi(sSize)

}

type CryptoClient interface {
	Algorithm() string
	Decrypt(cipherText []byte) ([]byte, error)
	Encrypt(plainText []byte) ([]byte, error)
	EncryptedSegmentSizeDefault(size int) int
	Key() []byte
	// Sign([]byte) ([]byte, error)
}

func NewCryptoClient(alg CryptoAlgorithm) (CryptoClient, error) {

	switch alg.Mode() {
	case "gcm":
		return newGCM(alg)
	default:
		return nil, errors.New("unsupported algorithm for tdf")
	}
}

func NewCryptoClientWithKey(alg CryptoAlgorithm, key []byte) (CryptoClient, error) {

	switch alg.Mode() {
	case "gcm":
		return newGCMWithKey(alg, key)
	default:
		return nil, errors.New("unsupported algorithm for tdf")
	}
}

func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func generateNonce(length int) ([]byte, error) {
	nonce := make([]byte, length)
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func Sign(alg crypto.Hash, msg []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	hexHash := make([]byte, hex.EncodedLen(mac.Size()))
	hex.Encode(hexHash, mac.Sum(nil))
	return hexHash
}

func GenerateRSAKeysPem(length int) (private []byte, public []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, err
	}

	//Encode private key
	privPkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	private = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privPkcs8,
		},
	)

	// Encode public key.
	pubPkcsx, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, err
	}
	public = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubPkcsx,
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return private, public, nil
}

func ParsePublicKey(key []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParseCertificate(block.Bytes)
}

func ParsePrivateKey(key []byte) (any, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}
