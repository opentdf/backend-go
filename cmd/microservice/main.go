package main

import "C"
import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v4"
	"github.com/miekg/pkcs11"
	"github.com/opentdf/backend-go/pkg/access"
	"golang.org/x/oauth2"
)

const kasName = "access-provider-000"
const hostname = "localhost"
const CkmCloudhsmAesKeyWrapZeroPad = pkcs11.CKM_VENDOR_DEFINED | 0x0000216F

func main() {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := access.Provider{
		URI:         *kasURI,
		PrivateKey:  getPrivateKey(kasName),
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
	id := os.Getenv("PKCS11_ID")
	label := os.Getenv("PKCS11_LABEL")
	slot, err := strconv.ParseInt(os.Getenv("PKCS11_SLOT"), 10, 32)
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
	if id != "" {
		var err error
		keyID, err = objectID(id)
		if err != nil {
			log.Fatalf("flag --key is invalid")
		}
	}

	//label := os.Getenv("PKCS11_LABEL")
	//rsaPub := readRSAPublicKey(wrappingKey)
	//if err != nil {
	//	log.Fatalf("error reading rsa public key: %v", err)
	//}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		log.Fatalf("error getting slots: %v", err)
	}
	log.Println(slots)
	if int(slot) >= len(slots) || slot < 0 {
		log.Fatalf("fail PKCS11_SLOT is invalid")
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

	log.Println("Finding key to wrap.")
	keyHandle, err := findKey(ctx, session, pkcs11.CKO_PRIVATE_KEY, keyID, label)
	if err != nil {
		log.Fatalf("error finding key: %v", err)
	}

	log.Println("Finding public key.")
	pubkeyHandle, err := findKey(ctx, session, pkcs11.CKO_PUBLIC_KEY, keyID, label)
	if err != nil {
		log.Fatalf("error finding key: %v", err)
	}
	log.Println(pubkeyHandle)
	log.Println(ctx.GetInfo())

	//template := []*pkcs11.Attribute{
	//	pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte("")),
	//	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	//	pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
	//	pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte("")),
	//	pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte("")),
	//}
	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, []byte("")),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	rsaPublicKey := rsa.PublicKey{
		N: nil,
		E: 0,
	}

	attrs, err := ctx.GetAttributeValue(session, pubkeyHandle, publicKeyTemplate)
	if err != nil {
		return
	}
	log.Println(attrs)
	for i, a := range attrs {
		log.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))
		if a.Type == pkcs11.CKA_PUBLIC_EXPONENT {
			exponent := big.NewInt(0)
			exponent.SetBytes(a.Value)
			rsaPublicKey.E = exponent
		}
		if a.Type == pkcs11.CKA_MODULUS {
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			log.Printf("modulus %s\n\n", mod.String())
			rsaPublicKey.N = mod
		}
	}
	//log.Println("Importing wrapping key.")
	//wrappingHandle, err := importWrappingKey(ctx, session, &rsaPub)
	//if err != nil {
	//	log.Fatalf("error importing wrapping key: %v", err)
	//}

	log.Println("Creating AES wrapping key.")
	aesHandle, err := createAESWrappingKey(ctx, session)
	if err != nil {
		log.Fatalf("error creating AES wrapping key: %v", err)
	}

	//log.Println("Wrapping AES key using RSA key.")
	//wrappedAESKey, err := ctx.WrapKey(session, []*pkcs11.Mechanism{
	//	pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, &pkcs11.OAEPParams{
	//		HashAlg:    pkcs11.CKM_SHA_1,
	//		MGF:        pkcs11.CKG_MGF1_SHA1,
	//		SourceType: pkcs11.CKZ_DATA_SPECIFIED,
	//		SourceData: nil,
	//	}),
	//}, wrappingHandle, aesHandle)
	//if err != nil {
	//	log.Fatalf("error wrapping AES key: %v", err)
	//}

	log.Println("Wrapping key using AES.")
	var mechanism uint
	cloudhsm := false
	if cloudhsm {
		mechanism = CkmCloudhsmAesKeyWrapZeroPad
	} else {
		mechanism = pkcs11.CKM_AES_KEY_WRAP_PAD
	}
	wrappedKey, err := ctx.WrapKey(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(
		mechanism, nil),
	}, aesHandle, keyHandle)
	if err != nil {
		log.Fatalf("error wrapping key: %v", err)
	}

	log.Println("Destroying AES wrapping key.")
	if err := ctx.DestroyObject(session, aesHandle); err != nil {
		log.Printf("error destroying AES wrapping key: %v\n", err)
	}

	os.Stdout.Write(wrappedKey)

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
	http.HandleFunc("/rewrap", kas.Handler)
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

func objectID(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	return hex.DecodeString(s)
}

func readRSAPublicKey(name string) rsa.PublicKey {
	fileBytes := loadBytes(name + "-public.pem")
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		log.Panic("empty block")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Panic(err)
	}
	return *publicKey
}

func getPrivateKey(name string) rsa.PrivateKey {
	fileBytes := loadBytes(name + "-private.pem")
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
	path := filepath.Join("testdata", name) // relative path
	fileBytes, err := ioutil.ReadFile(path)
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

func importWrappingKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, key *rsa.PublicKey) (pkcs11.ObjectHandle, error) {
	e := big.NewInt(int64(key.E))
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, []byte("wrapping-key")),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, key.N.Bytes()),
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, e.Bytes()),
	}
	return ctx.CreateObject(session, template)
}

func createAESWrappingKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, error) {
	return ctx.GenerateKey(session, []*pkcs11.Mechanism{
		pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil),
	}, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "aes-wrapping-key"),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32),
	})
}
