package access

import (
	"bytes"
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
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/opentdf/backend-go/pkg/nanotdf"
	"github.com/segmentio/asm/base64"
	"golang.org/x/crypto/hkdf"

	"github.com/opentdf/backend-go/pkg/p11"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/square/go-jose.v2/jwt"
)

const keyLength = 32
const ivSize = 12
const tagSize = 12

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

type customClaimsHeader struct {
	EntityID  string       `json:"sub"`
	ClientID  string       `json:"clientId"`
	TDFClaims ClaimsObject `json:"tdf_claims"`
}

// Handler decrypts and encrypts the symmetric data key
func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	slog.DebugContext(ctx, "REWRAP", "headers", r.Header, "body", r.Body, "ContentLength", r.ContentLength)

	// preflight
	if r.ContentLength == 0 {
		// TODO: What is this doing here?
		// If there is an empty body, should we return 400?
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	//////////////// OIDC VERIFY ///////////////
	// Check if Authorization header is present
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		slog.InfoContext(ctx, "no authorization header")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract OIDC token from the Authorization header
	oidcRequestToken := strings.TrimPrefix(authHeader, "Bearer ")
	if oidcRequestToken == authHeader {
		slog.InfoContext(ctx, "bearer token missing prefix")
		http.Error(w, "invalid authorization header format", http.StatusBadRequest)
		return
	}
	slog.DebugContext(ctx, "not a 401, probably", "oidcRequestToken", oidcRequestToken)

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(ctx, oidcRequestToken)
	if err != nil {
		http.Error(w, "forbidden", http.StatusBadRequest)
		slog.WarnContext(ctx, "Unable to verify", "err", err)
		return
	}

	oidcIssuerURL := os.Getenv("OIDC_ISSUER_URL")
	if !strings.HasPrefix(oidcIssuerURL, idToken.Issuer) {
		http.Error(w, "forbidden", http.StatusForbidden)
		slog.WarnContext(ctx, "Invalid token issuer", "issuer", idToken.Issuer, "oidcIssuerURL", oidcIssuerURL)
		return
	}

	// Extract custom claims
	var claims customClaimsHeader
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		slog.WarnContext(ctx, "unable to load claims", "err", err)
		return
	}
	slog.DebugContext(ctx, "verified", "claims", claims)

	//////////////// DECODE REQUEST BODY /////////////////////

	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err = decoder.Decode(&rewrapRequest)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		slog.WarnContext(ctx, "unable decode rewrap request", "err", err)
		return
	}
	requestToken, err := jwt.ParseSigned(rewrapRequest.SignedRequestToken)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		slog.WarnContext(ctx, "unable parse request", "err", err)
		return
	}
	var jwtClaimsBody jwt.Claims
	var bodyClaims customClaimsBody
	err = requestToken.UnsafeClaimsWithoutVerification(&jwtClaimsBody, &bodyClaims)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		slog.WarnContext(ctx, "unable decode request", "err", err)
		return
	}
	slog.DebugContext(ctx, "okay now we can check", "bodyClaims.RequestBody", bodyClaims.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		slog.WarnContext(ctx, "unable decode request body", "err", err)
		return
	}

	kasURL := os.Getenv("KAS_URL")
	if !strings.HasPrefix(requestBody.KeyAccess.URL, kasURL) {
		http.Error(w, "forbidden", http.StatusForbidden)
		slog.WarnContext(ctx, "invalid key access url", "keyAccessURL", requestBody.KeyAccess.URL, "oidcIssuerURL", oidcIssuerURL)
		return
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		responseBytes, err := nanoTDFRewrap(requestBody)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		_, _ = w.Write(responseBytes)
		return
	}

	///////////////////// EXTRACT POLICY /////////////////////
	slog.DebugContext(ctx, "extracting policy", "requestBody.policy", requestBody.Policy)
	// base 64 decode
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		http.Error(w, "Invalid policy", http.StatusBadRequest)
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return
	}

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		slog.WarnContext(ctx, "Could not get namespaces from policy!", "err", err)
		return
	}

	// this part goes in the plugin?
	slog.DebugContext(ctx, "Fetching attributes")
	definitions, err := fetchAttributes(ctx, namespaces)
	if err != nil {
		slog.ErrorContext(ctx, "Could not fetch attribute definitions from attributes service!", "err", err)
		http.Error(w, "attribute server request failure", http.StatusInternalServerError)
		return
	}
	slog.DebugContext(ctx, "fetch attributes", "definitions", definitions)

	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(ctx, claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		slog.WarnContext(ctx, "Could not perform access decision!", "err", err)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	if !access {
		slog.WarnContext(ctx, "Access Denied; no reason given")
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	/////////////////////EXTRACT CLIENT PUBKEY /////////////////////
	slog.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)

	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		slog.WarnContext(ctx, "missing clientPublicKey")
		http.Error(w, "clientPublicKey failure", http.StatusBadRequest)
		return
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		http.Error(w, "clientPublicKey parse failure", http.StatusBadRequest)
		return
	}

	// ///////////// UNWRAP AND REWRAP //////////////////

	// unwrap using hsm key
	symmetricKey, err := p11.DecryptOAEP(&p.Session, &p.PrivateKey,
		requestBody.KeyAccess.WrappedKey, crypto.SHA1, nil)
	if err != nil {
		slog.WarnContext(ctx, "failure to decrypt dek", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &clientPublicKey)
	if err != nil {
		slog.WarnContext(ctx, "rewrap: encryptWithPublicKey failed", "err", err, "clientPublicKey", &clientPublicKey)
		http.Error(w, "bad key for rewrap", http.StatusBadRequest)
		return
	}
	// // TODO validate policy
	// TODO: Yikes
	// slog.Println()

	// // TODO store policy
	// rewrappedKey := []byte("TODO")
	responseBytes, err := json.Marshal(&RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		slog.ErrorContext(ctx, "rewrap: marshall response failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(responseBytes)
	if err != nil {
		// FIXME Yikes what can we do?
		slog.ErrorContext(ctx, "rewrap: marshall response failed", "err", err)
	}
}

func nanoTDFRewrap(requestBody RequestBody) ([]byte, error) {
	header := requestBody.KeyAccess.Header

	headerReader := bytes.NewReader(header)

	nanoTDF, err := nanotdf.ReadNanoTDFHeader(headerReader)
	if err != nil {
		slog.Error("Could not fetch attribute definitions from attributes service!", "err", err)
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), nanoTDF.EphemeralPublicKey.Key)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal ephemeral public key")
	}

	kasEcPrivKeyFilePath := os.Getenv("KAS_PRIVATE_KEY")

	// Load PEM file
	raw, err := os.ReadFile(kasEcPrivKeyFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read KAS private key JSON data: %w", err)
	}

	block, _ := pem.Decode(raw)
	privateKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		slog.Error("Failed to encode private key to DER", "err", err)
	}

	symmetricKey, err := generateSymmetricKey(nanoTDF.EphemeralPublicKey.Key, privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		slog.Error("Failed to generate symmetric key", "err", err)
	}

	// Generate a private key
	privateKeyEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		slog.Error("Failed to create ec pair:", "err", err)
	}

	// Extract the public key from the private key
	publicKeyEphemeral := &privateKeyEphemeral.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKeyEphemeral)
	if err != nil {
		slog.Error("Failed to extract public key:", "err", err)
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
		slog.Error("Failed to parse public key PEM block", "err", err)
	}

	pub, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}
	sessionKey, err := generateSessionKey(pub, privateKeyEphemeral)
	if err != nil {
		slog.Error("Failed to generate session key", "err", err)
		return nil, err
	}

	cipherText, err := encryptKey(sessionKey, symmetricKey)
	if err != nil {
		slog.Error("Failed to encrypt key", "err", err)
		return nil, err
	}

	encoded := base64.StdEncoding.EncodeToString(cipherText)

	data := map[string]interface{}{
		"entityWrappedKey": encoded,
		"sessionPublicKey": pemString,
		"schemaVersion":    schemaVersion,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON data: %w", err)
	}

	return jsonData, nil
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
		slog.Error("Error unmarshalling elliptic point")
	}

	// ephemeralPublicKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	// symmetricKey, _ := privateKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	symmetricKey, _ := privateKey.Curve.ScalarMult(x, y, privateKey.D.Bytes())

	salt := versionSalt()

	hkdf := hkdf.New(sha256.New, symmetricKey.Bytes(), salt, nil)

	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	return derivedKey, nil
}

func generateSessionKey(ephemeralPublicKey *ecdsa.PublicKey, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sessionKey, _ := privateKey.Curve.ScalarMult(ephemeralPublicKey.X, ephemeralPublicKey.Y, privateKey.D.Bytes())
	salt := versionSalt()

	hkdf := hkdf.New(sha256.New, sessionKey.Bytes(), salt, nil)
	derivedKey := make([]byte, keyLength)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	return derivedKey, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) { //nolint:ireturn //no lint
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, nil
}

func encryptKey(sessionKey []byte, symmetricKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGcm, err := cipher.NewGCMWithTagSize(block, tagSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create NewGCMWithTagSize: %w", err)
	}

	iv := make([]byte, ivSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	cipherText := aesGcm.Seal(iv, iv, symmetricKey, nil)
	return cipherText, nil
}
