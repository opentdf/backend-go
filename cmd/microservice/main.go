package main

import "C"
import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/miekg/pkcs11"
	"github.com/opentdf/backend-go/internal/version"
	"github.com/opentdf/backend-go/pkg/access"
	"github.com/opentdf/backend-go/pkg/p11"
	"golang.org/x/oauth2"
)

const (
	ErrHsm             = Error("hsm unexpected")
	hostname           = "localhost"
	timeoutServerRead  = 5 * time.Second
	timeoutServerWrite = 10 * time.Second
	timeoutServerIdle  = 120 * time.Second
)

func loadIdentityProvider() oidc.IDTokenVerifier {
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	provider, err := oidc.NewProvider(context.Background(), oidcIssuer)
	if err != nil {
		slog.Error("OIDC_ISSUER provider fail", "err", err, "OIDC_ISSUER", oidcIssuer)
		panic(err)
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID},
	}
	slog.Debug("oauth configuring", "oauth2Config", oauth2Config)
	oidcConfig := oidc.Config{
		ClientID:                   "",
		SupportedSigningAlgs:       nil,
		SkipClientIDCheck:          true,
		SkipExpiryCheck:            false,
		SkipIssuerCheck:            false,
		Now:                        nil,
		InsecureSkipSignatureCheck: false,
	}
	return *provider.Verifier(&oidcConfig)
}

type hsmContext struct {
	pin string
	ctx *pkcs11.Ctx
}

type hsmSession struct {
	c       *hsmContext
	session pkcs11.SessionHandle
}

func newHSMContext() (*hsmContext, error) {
	pin := os.Getenv("PKCS11_PIN")
	pkcs11ModulePath := os.Getenv("PKCS11_MODULE_PATH")
	slog.Debug("loading pkcs11 module", "pkcs11ModulePath", pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if err := ctx.Initialize(); err != nil {
		return nil, errors.Join(ErrHsm, err)
	}

	hc := new(hsmContext)
	hc.pin = pin
	hc.ctx = ctx
	return hc, nil
}

func destroyHSMContext(hc *hsmContext) {
	defer hc.ctx.Destroy()
	err := hc.ctx.Finalize()
	if err != nil {
		slog.Error("pkcs11 error finalizing module", "err", err)
	}
}

func newHSMSession(hc *hsmContext) (*hsmSession, error) {
	slot, err := strconv.ParseInt(os.Getenv("PKCS11_SLOT_INDEX"), 10, 32)
	if err != nil {
		slog.Error("pkcs11 PKCS11_SLOT_INDEX parse error", "err", err, "PKCS11_SLOT_INDEX", os.Getenv("PKCS11_SLOT_INDEX"))
		return nil, errors.Join(ErrHsm, err)
	}

	slots, err := hc.ctx.GetSlotList(true)
	if err != nil {
		slog.Error("pkcs11 error getting slots", "err", err)
		return nil, errors.Join(ErrHsm, err)
	}
	if int(slot) >= len(slots) || slot < 0 {
		slog.Error("pkcs11 PKCS11_SLOT_INDEX is invalid", "slot_index", slot, "slots", slots)
		return nil, errors.Join(ErrHsm, err)
	}

	session, err := hc.ctx.OpenSession(slots[slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		slog.Error("pkcs11 error opening session", "slot_index", slot, "slots", slots)
		return nil, errors.Join(ErrHsm, err)
	}

	hs := new(hsmSession)
	hs.c = hc
	hs.session = session
	return hs, nil
}

func destroyHSMSession(hs *hsmSession) {
	err := hs.c.ctx.CloseSession(hs.session)
	if err != nil {
		slog.Error("pkcs11 error closing session", "err", err)
	}
}

func main() {
	// version and build information
	stats := version.GetVersion()

	format := os.Getenv("LOG_FORMAT")

	var logHandler slog.Handler
	switch format {
	case "json":
		logHandler = slog.NewJSONHandler(os.Stderr, nil)
	default:
		logHandler = slog.NewTextHandler(os.Stderr, nil)
	}

	slog.SetDefault(slog.New(logHandler))

	slog.Info("gokas-info", "version", stats.Version, "version_long", stats.VersionLong, "build_time", stats.BuildTime)

	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := access.Provider{
		URI:          *kasURI,
		PrivateKey:   p11.Pkcs11PrivateKeyRSA{},
		PublicKeyRsa: rsa.PublicKey{},
		PublicKeyEc:  ecdsa.PublicKey{},
		Certificate:  x509.Certificate{},
		Attributes:   nil,
		Session:      p11.Pkcs11Session{},
		OIDCVerifier: nil,
	}

	oidcVerifier := loadIdentityProvider()
	kas.OIDCVerifier = &oidcVerifier

	// PKCS#11
	hc, err := newHSMContext()
	if err != nil {
		slog.Error("pkcs11 error initializing hsm", "err", err)
		panic(err)
	}
	defer destroyHSMContext(hc)

	info, err := hc.ctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		panic(err)
	}
	slog.Info("pkcs11 module", "pkcs11info", info)

	hs, err := newHSMSession(hc)
	if err != nil {
		panic(err)
	}
	defer destroyHSMSession(hs)

	var keyID []byte

	err = hc.ctx.Login(hs.session, pkcs11.CKU_USER, hc.pin)
	if err != nil {
		slog.Error("pkcs11 error logging in as CKU USER", "err", err)
		panic(err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		err := ctx.Logout(sh)
		if err != nil {
			slog.Error("pkcs11 error logging out", "err", err)
		}
	}(hc.ctx, hs.session)

	info, err = hc.ctx.GetInfo()
	if err != nil {
		slog.Error("pkcs11 error querying module info", "err", err)
		panic(err)
	}
	slog.Info("pkcs11 module info after initialization", "pkcs11info", info)

	slog.Debug("Finding RSA key to wrap.")
	rsaLabel := os.Getenv("PKCS11_LABEL_PUBKEY_RSA") // development-rsa-kas
	keyHandle, err := findKey(hs, pkcs11.CKO_PRIVATE_KEY, keyID, rsaLabel)
	if err != nil {
		slog.Error("pkcs11 error finding key", "err", err)
		panic(err)
	}

	// set private key
	kas.PrivateKey = p11.NewPrivateKeyRSA(keyHandle)

	// initialize p11.pkcs11session
	kas.Session = p11.NewSession(hs.c.ctx, hs.session)

	// RSA Cert
	slog.Debug("Finding RSA certificate", "rsaLabel", rsaLabel)
	certHandle, err := findKey(hs, pkcs11.CKO_CERTIFICATE, keyID, rsaLabel)
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	if err != nil {
		slog.Error("pkcs11 error finding RSA cert", "err", err)
		panic(err)
	}
	attrs, err := hs.c.ctx.GetAttributeValue(hs.session, certHandle, certTemplate)
	if err != nil {
		slog.Error("pkcs11 error getting attribute from cert", "err", err)
		panic(err)
	}

	for _, a := range attrs {
		if a.Type == pkcs11.CKA_VALUE {
			certRsa, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				panic(err)
			}
			kas.Certificate = *certRsa
		}
	}

	// RSA Public key
	rsaPublicKey, ok := kas.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		slog.Error("public key RSA cert error")
		panic("public key RSA cert error")
	}
	kas.PublicKeyRsa = *rsaPublicKey

	// EC Cert
	var ecCert x509.Certificate
	ecLabel := os.Getenv("PKCS11_LABEL_PUBKEY_EC") // development-ec-kas
	certECHandle, err := findKey(hs, pkcs11.CKO_CERTIFICATE, keyID, ecLabel)
	if err != nil {
		slog.Error("public key EC cert error")
		panic("public key EC cert error")
	}
	certECTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	ecCertAttrs, err := hs.c.ctx.GetAttributeValue(hs.session, certECHandle, certECTemplate)
	if err != nil {
		slog.Error("public key EC cert error", "err", err)
		panic(err)
	}

	for _, a := range ecCertAttrs {
		if a.Type == pkcs11.CKA_VALUE {
			// exponent := big.NewInt(0)
			// exponent.SetBytes(a.Value)
			certEC, err := x509.ParseCertificate(a.Value)
			if err != nil {
				slog.Error("x509 parse error", "err", err)
				panic(err)
			}
			ecCert = *certEC
		}
	}

	// EC Public Key
	ecPublicKey, ok := ecCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		slog.Error("public key from cert fail for EC")
		panic("EC parse fail")
	}
	kas.PublicKeyEc = *ecPublicKey

	// os interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	// server
	server := http.Server{
		Addr:         "127.0.0.1:8080",
		ReadTimeout:  timeoutServerRead,
		WriteTimeout: timeoutServerWrite,
		IdleTimeout:  timeoutServerIdle,
	}
	http.HandleFunc("/kas_public_key", kas.CertificateHandler)
	http.HandleFunc("/v2/kas_public_key", kas.PublicKeyHandlerV2)
	http.HandleFunc("/v2/rewrap", kas.Handler)
	go func() {
		slog.Info("listening", "host", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			slog.Error("server failure")
			panic(err)
		}
	}()
	<-stop
	err = server.Shutdown(context.Background())
	if err != nil {
		slog.Error("server shutdown failure", "err", err)
	}
}

func findKey(hs *hsmSession, class uint, id []byte, label string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
	}
	if len(id) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}
	if label != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte(label)))
	}

	// CloudHSM does not support CKO_PRIVATE_KEY set to false
	if class == pkcs11.CKO_PRIVATE_KEY {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true))
	}
	var handle pkcs11.ObjectHandle
	var err error
	if err = hs.c.ctx.FindObjectsInit(hs.session, template); err != nil {
		return handle, errors.Join(ErrHsm, err)
	}
	defer func() {
		finalErr := hs.c.ctx.FindObjectsFinal(hs.session)
		if err == nil {
			err = finalErr
			slog.Error("server shutdown failure", "err", err)
		}
	}()

	var handles []pkcs11.ObjectHandle
	const maxHandles = 20
	handles, _, err = hs.c.ctx.FindObjects(hs.session, maxHandles)
	if err != nil {
		return handle, errors.Join(ErrHsm, err)
	}

	switch len(handles) {
	case 0:
		err = fmt.Errorf("key not found")
	case 1:
		handle = handles[0]
	default:
		err = fmt.Errorf("multiple key found")
	}

	return handle, err
}

type Error string

func (e Error) Error() string {
	return string(e)
}
