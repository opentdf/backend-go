package access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/opentdf/backend-go/pkg/nanotdf"
	"github.com/segmentio/asm/base64"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/opentdf/backend-go/pkg/p11"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/square/go-jose.v2/jwt"
)

type RewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"`
}

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Policy          string         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
}

type RewrapResponse struct {
	EntityWrappedKey []byte `json:"entityWrappedKey"`
	SessionPublicKey string `json:"sessionPublicKey"`
	SchemaVersion    string `json:"schemaVersion,omitempty"`
}

type customClaimsBody struct {
	RequestBody string `json:"requestBody,omitempty"`
}

type CustomClaimsHeader struct {
	EntityID  string       `json:"sub"`
	ClientID  string       `json:"clientId"`
	TDFClaims ClaimsObject `json:"tdf_claims"`
}

// Handler decrypts and encrypts the symmetric data key
func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	log.Println("REWRAP")
	log.Printf("headers %s", r.Header)
	log.Printf("body %s", r.Body)
	log.Printf("ContentLength %d", r.ContentLength)
	// preflight
	if r.ContentLength == 0 {
		return
	}

	//////////////// OIDC VERIFY ///////////////
	// Check if Authorization header is present
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := fmt.Fprint(w, "Missing Authorization header")
		if err != nil {
			log.Println(err)
			return
		}
		return
	}

	// Extract OIDC token from the Authorization header
	oidcRequestToken := strings.TrimPrefix(authHeader, "Bearer ")
	if oidcRequestToken == authHeader {
		w.WriteHeader(http.StatusBadRequest)
		_, err := fmt.Fprint(w, "Invalid Authorization header format")
		if err != nil {
			log.Println(err)
			return
		}
		return
	}

	log.Println(oidcRequestToken)

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(context.Background(), oidcRequestToken)
	if err != nil {
		log.Panic(err)
		return
	}

	// Extract custom claims
	var claims CustomClaimsHeader
	if err := idToken.Claims(&claims); err != nil {
		log.Panic(err)
		return
	}
	log.Println(claims)

	//////////////// DECODE REQUEST BODY /////////////////////

	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err = decoder.Decode(&rewrapRequest)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	requestToken, err := jwt.ParseSigned(rewrapRequest.SignedRequestToken)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	var jwtClaimsBody jwt.Claims
	var bodyClaims customClaimsBody
	err = requestToken.UnsafeClaimsWithoutVerification(&jwtClaimsBody, &bodyClaims)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	log.Println(bodyClaims.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		log.Println("jwtclaims")
		log.Println(jwtClaimsBody)
		log.Println("bodyclaims")
		log.Println(bodyClaims)
		//log.Fatal("Nano not implemented yet")
		responseBytes, err := NanoTDFRewrap(requestBody, r.Header, claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write(responseBytes)
		return
	}

	///////////////////// EXTRACT POLICY /////////////////////
	log.Println(requestBody.Policy)
	// base 64 decode
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		// logger.Errorf("Could not get namespaces from policy! Error was %s", err)
		log.Printf("Could not get namespaces from policy! Error was %s", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// this part goes in the plugin?
	log.Println("Fetching attributes")
	definitions, err := fetchAttributes(r.Context(), namespaces)
	if err != nil {
		// logger.Errorf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		log.Printf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("%+v", definitions)

	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		// logger.Errorf("Could not perform access decision! Error was %s", err)
		log.Printf("Could not perform access decision! Error was %s", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !access {
		log.Println("not authorized")
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	/////////////////////EXTRACT CLIENT PUBKEY /////////////////////
	log.Println(requestBody.ClientPublicKey)

	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		// FIXME handle error
		log.Panic("err missing clientPublicKey")
		return
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// ///////////////////////////////

	// nano header
	log.Println(requestBody.KeyAccess.Header)
	log.Println(len(requestBody.KeyAccess.Header))

	if err != nil {
		log.Panic(err)
	}
	//log.Print(n.Header.Length)

	// unwrap using a key from file
	// ciphertext, _ := hex.DecodeString(requestBody.KeyAccess.WrappedKey)
	// symmetricKey, err := tdf3.DecryptWithPrivateKey(requestBody.KeyAccess.WrappedKey, &p.PrivateKey)
	// if err != nil {
	// 	// FIXME handle error
	// 	log.Panic(err)
	// 	return
	// }

	// ///////////// UNWRAP AND REWRAP //////////////////

	// unwrap using hsm key
	symmetricKey, err := p11.DecryptOAEP(&p.Session, &p.PrivateKey,
		requestBody.KeyAccess.WrappedKey, crypto.SHA1, nil)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &clientPublicKey)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// // TODO validate policy
	// log.Println()

	// // TODO store policy
	// rewrappedKey := []byte("TODO")
	responseBytes, err := json.Marshal(&RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(responseBytes)
}

func NanoTDFRewrap(requestBody RequestBody, headers http.Header, claims CustomClaimsHeader) ([]byte, error) {

	header := requestBody.KeyAccess.Header

	headerReader := bytes.NewReader(header)

	nanoTDF, err := nanotdf.ReadNanoTDFHeader(headerReader)
	if err != nil {
		fmt.Println("Error:", err)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), nanoTDF.EphemeralPublicKey.Key)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal ephemeral public key")
	}

	kasEcPrivKeyFilePath := os.Getenv("KAS_PRIVATE_KEY")

	// Load PEM file
	raw, err := os.ReadFile(kasEcPrivKeyFilePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	privateKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		fmt.Errorf("Failed to encode private key to DER:", err)
	}

	symmetricKey, err := generateSymmetricKey(nanoTDF.EphemeralPublicKey.Key, privateKey.(*ecdsa.PrivateKey))
	fmt.Println("%x", symmetricKey)
	if err != nil {
		fmt.Errorf("Failed to generate symmetric key", err)
	}

	// Generate a private key
	privateKeyEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Errorf("Failed to create ec pair:", err)
	}

	// Extract the public key from the private key
	publicKeyEphemeral := &privateKeyEphemeral.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKeyEphemeral)
	if err != nil {
		fmt.Errorf("Failed to extract public key:", err)
	}

	// Create a PEM block
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pemString := string(pem.EncodeToMemory(pemBlock))

	clientPublicKey := requestBody.ClientPublicKey
	block, _ = pem.Decode([]byte(clientPublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}
	sessionKey, err := generateSessionKey(pub, privateKeyEphemeral)
	if err != nil {
		fmt.Errorf("Failed to generate session key")
		return nil, err
	}

	cipherText, err := encryptKey(sessionKey, symmetricKey)
	if err != nil {
		fmt.Errorf("Failed to encrypt key")
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(cipherText)

	data := map[string]interface{}{
		"entityWrappedKey": encoded,
		"sessionPublicKey": pemString,
		"schemaVersion":    schemaVersion,
	}

	return json.Marshal(data)

}

func versionSalt() []byte {
	digest := sha256.New()
	digest.Write([]byte("L1L"))
	return digest.Sum(nil)
}

func generateSymmetricKey(ephemeralPublicKeyBytes []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	curve := elliptic.P256()

	x, y := elliptic.UnmarshalCompressed(curve, ephemeralPublicKeyBytes)
	if x == nil {
		fmt.Println("Error unmarshalling point")
	}

	ephemeralPublicKey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	symmetricKey, _ := privateKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	fmt.Printf("%x\n:", symmetricKey)

	salt := versionSalt()

	hkdf := hkdf.New(sha256.New, symmetricKey.Bytes(), salt, nil)

	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, err
	}
	fmt.Printf("derived %x\n : ", derivedKey)

	return derivedKey, nil
}

func generateSessionKey(ephemeralPublicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sessionKey, _ := privateKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	salt := versionSalt()

	hkdf := hkdf.New(sha256.New, sessionKey.Bytes(), salt, nil)
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, err
	}

	return derivedKey, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}

func encryptKey(sessionKey []byte, symmetricKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	aesGcm, err := cipher.NewGCMWithTagSize(block, 12)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 12)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipherText := aesGcm.Seal(iv, iv, symmetricKey, nil)
	return cipherText, nil
}
