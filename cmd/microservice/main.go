package main

import "C"
import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v4"
	"github.com/miekg/pkcs11"
	"github.com/opentdf/backend-go/pkg/access"
	"golang.org/x/oauth2"
)

const kasName = "access-provider-000"
const hostname = "localhost"

func main() {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := access.Provider{
		URI:         *kasURI,
		PrivateKey:  getPrivateKey(),
		Certificate: x509.Certificate{},
		Attributes:  nil,
	}
	// OIDC
	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		// handle error
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.Println(oauth2Config)

	// PKCS#11
	pin := os.Getenv("PKCS11_PIN")
	rsaLabel := os.Getenv("PKCS11_LABEL_PUBKEY_RSA") //development-rsa-kas
	ecLabel := os.Getenv("PKCS11_LABEL_PUBKEY_EC") //development-ec-kas
	slot, err := strconv.ParseInt(os.Getenv("PKCS11_SLOT_INDEX"), 10, 32)
	if err != nil {
		log.Fatalf("PKCS11_SLOT parse error: %v", err)
	}
	pkcs11ModulePath := os.Getenv("PKCS11_MODULE_PATH")
	log.Println(pkcs11ModulePath)
	ctx := pkcs11.New(pkcs11ModulePath)
	if err := ctx.Initialize(); err != nil {
		log.Fatalf("error initializing module: %v", err)
	}
	defer ctx.Destroy()
	defer ctx.Finalize()
	log.Println(ctx.GetInfo())
	var keyID []byte
	//id := os.Getenv("PKCS11_ID")
	//if id != "" {
	//	var err error
	//	keyID, err = objectID(id)
	//	if err != nil {
	//		log.Fatalf("flag --key is invalid")
	//	}
	//}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		log.Fatalf("error getting slots: %v", err)
	}
	log.Println(slots)
	if int(slot) >= len(slots) || slot < 0 {
		log.Fatalf("fail PKCS11_SLOT_INDEX is invalid")
	}
	log.Println(slots[slot])
	session, err := ctx.OpenSession(slots[slot], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("error opening session: %v", err)
	}
	defer ctx.CloseSession(session)

	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		log.Fatalf("error logging in: %v", err)
	}
	defer ctx.Logout(session)
	log.Println(ctx.GetInfo())
	log.Println("Finding RSA key to wrap.")
	keyHandle, err := findKey(ctx, session, pkcs11.CKO_PRIVATE_KEY, keyID, rsaLabel)
	if err != nil {
		log.Fatalf("error finding key: %v", err)
	}
	log.Println(keyHandle)




	//RSA Cert
	log.Println("Finding RSA cert.")
	certHandle, err := findKey(ctx, session, pkcs11.CKO_CERTIFICATE, keyID, rsaLabel)
	certTemplate := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
        pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
        pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
        pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
    }
	attrs, err := ctx.GetAttributeValue(session, certHandle, certTemplate)
	if err != nil {
		log.Panic(err)
	}
	log.Println(attrs)

	for i, a := range attrs {
		log.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))
		if a.Type == pkcs11.CKA_VALUE {
			certRsa,err := x509.ParseCertificate(a.Value)
			if err != nil {
				log.Panic(err)
			}
			kas.Certificate = *certRsa
		}
	}


	// RSA Public key
	log.Println("Finding RSA public key from cert.")
	rsaPublicKey := kas.Certificate.PublicKey.(*rsa.PublicKey)
	kas.PublicKeyRsa = *rsaPublicKey
	


	//EC Cert
	log.Println("Finding EC cert.")
	ec_cert := x509.Certificate{}

	certECHandle, err := findKey(ctx, session, pkcs11.CKO_CERTIFICATE, keyID, ecLabel)
	certECTemplate := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
        pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
        pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
        pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("")),
        pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, []byte("")),
    }
	ecCertAttrs, err := ctx.GetAttributeValue(session, certECHandle, certECTemplate)
	if err != nil {
		log.Panic(err)
	}
	log.Println(ecCertAttrs)

	for i, a := range ecCertAttrs {
		log.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))
		if a.Type == pkcs11.CKA_VALUE {
			// exponent := big.NewInt(0)
			// exponent.SetBytes(a.Value)
			certEC,err := x509.ParseCertificate(a.Value)
			if err != nil {
				log.Panic(err)
			}
			ec_cert = *certEC
		}
	}


	// EC Public Key
	log.Println("Finding EC public key from cert.")
	log.Println(ec_cert.PublicKeyAlgorithm)
	ec_public_key := ec_cert.PublicKey.(*ecdsa.PublicKey)
	kas.PublicKeyEc = *ec_public_key

	// Open up our database connection.
	config, err := pgx.ParseConfig("postgres://host:5432/database?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	config.Host = os.Getenv("POSTGRES_HOST")
	config.Database = os.Getenv("POSTGRES_DATABASE")
	config.User = os.Getenv("POSTGRES_USER")
	config.Password = os.Getenv("POSTGRES_PASSWORD")
	config.LogLevel = pgx.LogLevelTrace
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	//defer the close till after the main function has finished	executing
	defer conn.Close(context.Background())
	var greeting string
	//
	conn.QueryRow(context.Background(), "select 1").Scan(&greeting)
	fmt.Println(greeting)

	// os interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	// server
	server := http.Server{
		Addr:         "127.0.0.1:8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	http.HandleFunc("/kas_public_key", kas.CertificateHandler)
	http.HandleFunc("/v2/kas_public_key", kas.PublicKeyHandlerV2)
	http.HandleFunc("/v2/rewrap", kas.Handler)
	go func() {
		log.Printf("listening on http://%s", server.Addr)
		log.Printf(os.Getenv("SERVICE"))
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	<-stop
	err = server.Shutdown(context.Background())
	if err != nil {
		log.Println(err)
	}
}

//func objectID(s string) ([]byte, error) {
//	s = strings.TrimPrefix(strings.ToLower(s), "0x")
//	return hex.DecodeString(s)
//}

func getPrivateKey() rsa.PrivateKey {
	privkey := os.Getenv("PRIVATE_KEY_RSA_PATH")
	fileBytes := loadBytes(privkey)
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		log.Panic("empty block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panic(err)
	}
	return *privateKey
}

func loadBytes(name string) []byte {
	pk := os.Getenv("PRIVATE_KEY")
	if pk != "" {
		return []byte(pk)
	}
	//path := filepath.Join("..","..",name) // relative path
	log.Println(name)
	fileBytes, err := ioutil.ReadFile(name)
	if err != nil {
		log.Panic(err)
	}
	return fileBytes
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, id []byte, label string) (handle pkcs11.ObjectHandle, err error) {
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

	if err = ctx.FindObjectsInit(session, template); err != nil {
		return
	}
	defer func() {
		finalErr := ctx.FindObjectsFinal(session)
		if err == nil {
			err = finalErr
		}
	}()

	var handles []pkcs11.ObjectHandle
	handles, _, err = ctx.FindObjects(session, 20)
	if err != nil {
		return
	}
	switch len(handles) {
	case 0:
		err = fmt.Errorf("key not found")
	case 1:
		handle = handles[0]
	default:
		err = fmt.Errorf("multiple key found")
	}

	return
}

func getPublic(point []byte) (pub *ecdsa.PublicKey, err error) {
	var ecdsaPub ecdsa.PublicKey

	ecdsaPub.Curve = elliptic.P256()
	pointLength := ecdsaPub.Curve.Params().BitSize/8*2 + 1
	if len(point) != pointLength {
		err = fmt.Errorf("CKA_EC_POINT (%d) does not fit used curve (%d)", len(point), pointLength)
		return
	}
	ecdsaPub.X, ecdsaPub.Y = elliptic.Unmarshal(ecdsaPub.Curve, point[:pointLength])
	if ecdsaPub.X == nil {
		err = fmt.Errorf("failed to decode CKA_EC_POINT")
		return
	}
	if !ecdsaPub.Curve.IsOnCurve(ecdsaPub.X, ecdsaPub.Y) {
		err = fmt.Errorf("public key is not on Curve")
		return
	}

	pub = &ecdsaPub
	return
}
