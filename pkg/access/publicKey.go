package access

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const (
	ErrCertificateEncode = Error("certificate encode error")
	ErrPublicKeyMarshal  = Error("public key marshal error")
	algorithmEc256       = "ec:secp256r1"
)

func (p *Provider) CertificateHandler(w http.ResponseWriter, r *http.Request) {
	log := p.Logger
	algorithm := r.URL.Query().Get("algorithm")
	if algorithm == algorithmEc256 {
		ecPublicKeyPem, err := exportEcPublicKeyAsPemStr(&p.PublicKeyEc)
		if err != nil {
			log.Error("EC public key from PKCS11", "err", err)
			panic(err)
		}
		_, _ = w.Write([]byte(ecPublicKeyPem))
		return
	}
	certificatePem, err := exportCertificateAsPemStr(&p.Certificate)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error("RSA public key from PKCS11", "err", err)
		return
	}
	log.Debug("Cert Handler found", "cert", certificatePem)
	jData, err := json.Marshal(certificatePem)
	if err != nil {
		log.Error("json certificate Marshal", "err", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jData)
	_, _ = w.Write([]byte("\n")) // added so that /kas_public_key matches opentdf response exactly
}

// PublicKeyHandlerV2 decrypts and encrypts the symmetric data key
func (p *Provider) PublicKeyHandlerV2(w http.ResponseWriter, r *http.Request) {
	log := p.Logger
	algorithm := r.URL.Query().Get("algorithm")
	// ?algorithm=ec:secp256r1
	if algorithm == algorithmEc256 {
		ecPublicKeyPem, err := exportEcPublicKeyAsPemStr(&p.PublicKeyEc)
		if err != nil {
			// XXX Should be writing these? What happens?
			// w.WriteHeader(http.StatusInternalServerError)
			log.Error("EC public key from PKCS11", "err", err)
			return
		}
		_, _ = w.Write([]byte(ecPublicKeyPem))
		return
	}
	format := r.URL.Query().Get("format")
	if format == "jwk" {
		// Parse, serialize, slice and dice JWKs!
		rsaPublicKeyJwk, err := jwk.FromRaw(&p.PublicKeyRsa)
		if err != nil {
			log.Error("failed to parse JWK", "err", err)
			return
		}
		// Keys can be serialized back to JSON
		jsonPublicKey, err := json.Marshal(rsaPublicKeyJwk)
		if err != nil {
			log.Error("failed to marshal JWK", "err", err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jsonPublicKey)
		return
	}
	rsaPublicKeyPem, err := exportRsaPublicKeyAsPemStr(&p.PublicKeyRsa)
	if err != nil {
		log.Error("export RSA public key", "err", err)
		return
	}
	_, _ = w.Write([]byte(rsaPublicKeyPem))
}

func exportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportEcPublicKeyAsPemStr(pubkey *ecdsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", errors.Join(ErrPublicKeyMarshal, err)
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "PUBLIC KEY",
			Headers: nil,
			Bytes:   pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

func exportCertificateAsPemStr(cert *x509.Certificate) (string, error) {
	certBytes := cert.Raw
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   certBytes,
		},
	)
	if certPem == nil {
		return "", ErrCertificateEncode
	}
	return string(certPem), nil
}

type Error string

func (e Error) Error() string {
	return string(e)
}
