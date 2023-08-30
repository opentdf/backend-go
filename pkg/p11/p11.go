package p11

import (
	"crypto"
	"errors"

	"github.com/miekg/pkcs11"
)

// See https://github.com/ThalesIgnite/crypto11/blob/d334790e12893aa2f8a2c454b16003dfd9f7d2de/rsa.go
const (
	ErrUnsupportedRSAOptions = Error("hsm unsupported RSA option value")
	ErrHsmDecrypt            = Error("hsm decrypt error")
)

type Pkcs11Session struct {
	ctx    *pkcs11.Ctx
	handle pkcs11.SessionHandle
}

type Pkcs11PrivateKeyRSA struct {
	handle pkcs11.ObjectHandle
}

func NewSession(ctx *pkcs11.Ctx, handle pkcs11.SessionHandle) Pkcs11Session {
	return Pkcs11Session{
		handle: handle,
		ctx:    ctx,
	}
}

func NewPrivateKeyRSA(handle pkcs11.ObjectHandle) Pkcs11PrivateKeyRSA {
	return Pkcs11PrivateKeyRSA{
		handle: handle,
	}
}

func DecryptOAEP(session *Pkcs11Session, key *Pkcs11PrivateKeyRSA, ciphertext []byte, hashFunction crypto.Hash, label []byte) ([]byte, error) {
	hashAlg, mgfAlg, _, err := hashToPKCS11(hashFunction)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}

	mech := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(hashAlg, mgfAlg, pkcs11.CKZ_DATA_SPECIFIED, label))

	err = session.ctx.DecryptInit(session.handle, []*pkcs11.Mechanism{mech}, key.handle)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}
	decrypt, err := session.ctx.Decrypt(session.handle, ciphertext)
	if err != nil {
		return nil, errors.Join(ErrHsmDecrypt, err)
	}
	return decrypt, nil
}

func hashToPKCS11(hashFunction crypto.Hash) (hashAlg uint, mgfAlg uint, hashLen uint, err error) {
	switch hashFunction {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, 20, nil
	case crypto.SHA224:
		return pkcs11.CKM_SHA224, pkcs11.CKG_MGF1_SHA224, 28, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, 32, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, 48, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, 64, nil
	default:
		return 0, 0, 0, ErrUnsupportedRSAOptions
	}
}

type Error string

func (e Error) Error() string {
	return string(e)
}
