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
	"plugin"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/miekg/pkcs11"
	"github.com/opentdf/backend-go/internal/version"
	"github.com/opentdf/backend-go/pkg/access"
	"github.com/opentdf/backend-go/pkg/p11"
	"golang.org/x/oauth2"
)

var log = slog.New(slog.NewTextHandler(os.Stdout, nil))

const (
	ErrHsm             = Error("hsm unexpected")
	hostname           = "localhost"
	timeoutServerRead  = 5 * time.Second
	timeoutServerWrite = 10 * time.Second
	timeoutServerIdle  = 120 * time.Second
)

type IMiddleware interface {
	AuditHook(f http.HandlerFunc) http.HandlerFunc
}

func loadAuditHook() func(f http.HandlerFunc) http.HandlerFunc {
	// TODO Use AUDIT_ENABLED env for connection audit_hooks for attributes
	auditEnabled := os.Getenv("AUDIT_ENABLED")
	log.Debug("loadAuditHook", "AUDIT_ENABLED", auditEnabled)

	plug, err := plugin.Open("audit_hooks.so")
	if err != nil {
		panic(err)
	}
	symMiddleware, err := plug.Lookup("Middleware")
	if err != nil {
		panic(err)
	}
	mid, _ := symMiddleware.(IMiddleware)

	return mid.AuditHook
}

func main() {
	// version and build information
	stats := version.GetVersion()
	log.Info("INIT", "Version", stats.Version, "Version Long", stats.VersionLong, "Build Time", stats.BuildTime)

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
	// OIDC
	oidcIssuer := os.Getenv("OIDC_ISSUER")
	provider, err := oidc.NewProvider(context.Background(), oidcIssuer)
	if err != nil {
		log.Error("OIDC Init failed", "Err", err)
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
	log.Info("initializing oauth2", "oauth2", oauth2Config)
	oidcConfig := oidc.Config{
		ClientID:                   "",
		SupportedSigningAlgs:       nil,
		SkipClientIDCheck:          true,
		SkipExpiryCheck:            false,
		SkipIssuerCheck:            false,
		Now:                        nil,
		InsecureSkipSignatureCheck: false,
	}
	var verifier = provider.Verifier(&oidcConfig)

	kas.OIDCVerifier = verifier

	// PKCS#11
	pin := os.Getenv("PKCS11_PIN")
	rsaLabel := os.Getenv("PKCS11_LABEL_PUBKEY_RSA") // development-rsa-kas
	ecLabel := os.Getenv("PKCS11_LABEL_PUBKEY_EC")   // development-ec-kas
	slot, err := strconv.ParseInt(os.Getenv("PKCS11_SLOT_INDEX"), 10, 32)
	if err != nil {
		log.Error("PKCS11_SLOT_INDEX parse error", "err", err)
		os.Exit(1)
	}
	pkcs11ModulePath := os.Getenv("PKCS11_MODULE_PATH")
	log.Debug("pkcs11ModulePath", "PKCS11_MODULE_PATH", pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if err := ctx.Initialize(); err != nil {
		log.Error("error initializing pkcs11 module", "err", err)
		os.Exit(1)
	}
	defer ctx.Destroy()
	defer func(ctx *pkcs11.Ctx) {
		err := ctx.Finalize()
		if err != nil {
			log.Error("error finalizing pkcs11 module", "err", err)
		}
	}(ctx)
	info, err := ctx.GetInfo()
	if err != nil {
		log.Error("error inspecting pkcs11 module", "err", err)
		os.Exit(1)
	}
	log.Info("initializing PKCS11 context", "info", info)
	var keyID []byte
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		log.Error("error getting slots", "err", err)
		panic(err)
	}
	log.Info("acquired PKCS11 slots", "slots", slots)
	if int(slot) >= len(slots) || slot < 0 {
		log.Error("fail PKCS11_SLOT_INDEX is invalid")
		panic("slotfail")
	}
	log.Info("Selected slot", "slot", slots[slot])
	session, err := ctx.OpenSession(slots[slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Error("error opening session", "err", err)
		panic(err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		err := ctx.CloseSession(sh)
		if err != nil {
			log.Error("error closing session", "err", err)
		}
	}(ctx, session)

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Error("error logging in", "err", err)
		panic(err)
	}
	defer func(ctx *pkcs11.Ctx, sh pkcs11.SessionHandle) {
		err := ctx.Logout(sh)
		if err != nil {
			log.Error("error logging out", "err", err)
		}
	}(ctx, session)
	info, err = ctx.GetInfo()
	if err != nil {
		log.Error("error inspecting pkcs11 module", "err", err)
		os.Exit(1)
	}
	log.Info("PKCS11 state after configuration", "info", info)

	log.Info("Finding RSA key to wrap.")
	keyHandle, err := findKey(ctx, session, pkcs11.CKO_PRIVATE_KEY, keyID, rsaLabel)
	if err != nil {
		log.Error("error finding key", "err", err)
		panic(err)
	}
	log.Info("Found key", "handle", keyHandle)

	// set private key
	kas.PrivateKey = p11.NewPrivateKeyRSA(keyHandle)

	// initialize p11.pkcs11session
	kas.Session = p11.NewSession(ctx, session)

	// RSA Cert
	log.Info("Finding RSA certificate", "label", rsaLabel)
	certHandle, err := findKey(ctx, session, pkcs11.CKO_CERTIFICATE, keyID, rsaLabel)
	if err != nil {
		log.Error("error finding cert", "err", err)
		panic(err)
	}
	certTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	attrs, err := ctx.GetAttributeValue(session, certHandle, certTemplate)
	if err != nil {
		log.Error("Unable to get attribute value", "err", err)
		panic(err)
	}
	log.Info("Got attribute value", "attrs", attrs)

	for i, a := range attrs {
		log.Info("verifying", "attr", i, "type", a.Type, "valuelen", len(a.Value))
		if a.Type == pkcs11.CKA_VALUE {
			certRsa, err := x509.ParseCertificate(a.Value)
			if err != nil {
				log.Error("Unable to parse attribute cert", "err", err)
				panic(err)
			}
			kas.Certificate = *certRsa
		}
	}

	// RSA Public key
	log.Info("Finding RSA public key from cert")
	rsaPublicKey, ok := kas.Certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Error("RSA public key from cert error", "err", err)
		panic(err)
	}
	kas.PublicKeyRsa = *rsaPublicKey

	// EC Cert
	log.Info("Finding EC cert.")
	var ecCert x509.Certificate

	certECHandle, err := findKey(ctx, session, pkcs11.CKO_CERTIFICATE, keyID, ecLabel)
	if err != nil {
		log.Error("EC public key find fail", "err", err)
		panic(err)
	}
	certECTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
	}
	ecCertAttrs, err := ctx.GetAttributeValue(session, certECHandle, certECTemplate)
	if err != nil {
		log.Error("EC GetAttributeValue failure", "err", err)
		panic(err)
	}
	log.Info("ec GetAttributeValue", "ecCertAttrs", ecCertAttrs)

	for i, a := range ecCertAttrs {
		log.Info("verifying", "attr", i, "type", a.Type, "valuelen", len(a.Value))
		if a.Type == pkcs11.CKA_VALUE {
			// exponent := big.NewInt(0)
			// exponent.SetBytes(a.Value)
			certEC, err := x509.ParseCertificate(a.Value)
			if err != nil {
				log.Error("EC ParseCertificate failure", "err", err)
				panic(err)
			}
			ecCert = *certEC
		}
	}

	// EC Public Key
	log.Info("Finding EC public key from cert", "algorithm", ecCert.PublicKeyAlgorithm)
	ecPublicKey, ok := ecCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Error("EC PublicKey failure")
		panic(1)
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

	auditHook := loadAuditHook()

	http.HandleFunc("/kas_public_key", kas.CertificateHandler)
	// TODO mid.AuditHook should be in attributes module
	// http.HandleFunc("/v2/kas_public_key", kas.PublicKeyHandlerV2)
	http.HandleFunc("/v2/kas_public_key", auditHook(kas.PublicKeyHandlerV2))
	http.HandleFunc("/v2/rewrap", kas.Handler)

	go func() {
		log.Info("listening", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			log.Error("ListenAndServe error", "err", err)
			os.Exit(1)
		}
	}()
	<-stop
	err = server.Shutdown(context.Background())
	if err != nil {
		log.Error("Shutdown error", "err", err)
	}
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, id []byte, label string) (pkcs11.ObjectHandle, error) {
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
	if err = ctx.FindObjectsInit(session, template); err != nil {
		return handle, errors.Join(ErrHsm, err)
	}
	defer func() {
		finalErr := ctx.FindObjectsFinal(session)
		if err == nil {
			err = finalErr
		}
	}()

	var handles []pkcs11.ObjectHandle
	const maxHandles = 20
	handles, _, err = ctx.FindObjects(session, maxHandles)
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
