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
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/opentdf/backend-go/pkg/nanotdf"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/opentdf/backend-go/pkg/p11"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/square/go-jose.v2/jwt"
)

const keyLength = 32
const ivSize = 12
const tagSize = 12

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Policy          string         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
}

type customClaimsBody struct {
	RequestBody string `json:"requestBody,omitempty"`
}

type customClaimsHeader struct {
	EntityID  string       `json:"sub"`
	ClientID  string       `json:"clientId"`
	TDFClaims ClaimsObject `json:"tdf_claims"`
}

const (
	ErrUser     = Error("request error")
	ErrInternal = Error("internal error")
)

func err400(s string) error {
	return errors.Join(ErrUser, status.Error(codes.InvalidArgument, s))
}

func err401(s string) error {
	return errors.Join(ErrUser, status.Error(codes.Unauthenticated, s))
}

func err403(s string) error {
	return errors.Join(ErrUser, status.Error(codes.PermissionDenied, s))
}

func err503(s string) error {
	return errors.Join(ErrInternal, status.Error(codes.Unavailable, s))
}

func (p *Provider) Rewrap(ctx context.Context, in *RewrapRequest) (*RewrapResponse, error) {
	slog.DebugContext(ctx, "REWRAP")

	bearer := in.Bearer
	if bearer == "" {
		slog.Info("Bearer not set; investigatint authorization header")
		// Check for bearer token in Authorization header
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			authHeaders := md.Get("Authorization")
			if len(authHeaders) == 0 {
				slog.InfoContext(ctx, "no authorization header")
				return nil, err401("no auth token")
			}
			if len(authHeaders) != 1 {
				slog.InfoContext(ctx, "authorization header repetition")
				return nil, err401("auth fail")
			}
			bearer = strings.TrimPrefix(authHeaders[0], "Bearer ")
			if bearer == authHeaders[0] {
				slog.InfoContext(ctx, "bearer token missing prefix")
				return nil, err401("invalid authorization header format")
			}
		}
	}

	// Extract OIDC token from the Authorization header
	slog.DebugContext(ctx, "not a 401, probably", "oidcRequestToken", bearer)

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(ctx, bearer)
	if err != nil {
		slog.WarnContext(ctx, "Unable to verify", "err", err)
		return nil, err403("forbidden")
	}

	oidcIssuerURL := os.Getenv("OIDC_ISSUER_URL")
	if !strings.HasPrefix(oidcIssuerURL, idToken.Issuer) {
		slog.WarnContext(ctx, "Invalid token issuer", "issuer", idToken.Issuer, "oidcIssuerURL", oidcIssuerURL)
		return nil, err403("forbidden")
	}

	// Extract custom claims
	var claims customClaimsHeader
	if err := idToken.Claims(&claims); err != nil {
		slog.WarnContext(ctx, "unable to load claims", "err", err)
		return nil, err403("forbidden")
	}
	slog.DebugContext(ctx, "verified", "claims", claims)

	//////////////// DECODE REQUEST BODY /////////////////////

	requestToken, err := jwt.ParseSigned(in.SignedRequestToken)
	if err != nil {
		slog.WarnContext(ctx, "unable parse request", "err", err)
		return nil, err400("bad request")
	}
	var jwtClaimsBody jwt.Claims
	var bodyClaims customClaimsBody
	err = requestToken.UnsafeClaimsWithoutVerification(&jwtClaimsBody, &bodyClaims)
	if err != nil {
		slog.WarnContext(ctx, "unable decode request", "err", err)
		return nil, err400("bad request")
	}
	slog.DebugContext(ctx, "okay now we can check", "bodyClaims.RequestBody", bodyClaims.RequestBody)
	decoder := json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		slog.WarnContext(ctx, "unable decode request body", "err", err)
		return nil, err400("bad request")
	}

	kasURL := os.Getenv("KAS_URL")
	if !strings.HasPrefix(requestBody.KeyAccess.URL, kasURL) {
		slog.WarnContext(ctx, "invalid key access url", "keyAccessURL", requestBody.KeyAccess.URL, "oidcIssuerURL", oidcIssuerURL)
		return nil, err403("forbidden")
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		return nanoTDFRewrap(requestBody)
	}

	///////////////////// EXTRACT POLICY /////////////////////
	slog.DebugContext(ctx, "extracting policy", "requestBody.policy", requestBody.Policy)
	// base 64 decode
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		slog.WarnContext(ctx, "Could not get namespaces from policy!", "err", err)
		return nil, err403("forbidden")
	}

	// this part goes in the plugin?
	slog.DebugContext(ctx, "Fetching attributes", "policy.namespaces", namespaces, "policy.body", policy.Body)
	definitions, err := p.fetchAttributes(ctx, namespaces)
	if err != nil {
		slog.ErrorContext(ctx, "Could not fetch attribute definitions from attributes service!", "err", err)
		return nil, err503("attribute server request failure")
	}
	slog.DebugContext(ctx, "fetch attributes", "definitions", definitions)

	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(ctx, claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		slog.WarnContext(ctx, "Could not perform access decision!", "err", err)
		return nil, err403("forbidden")
	}

	if !access {
		slog.WarnContext(ctx, "Access Denied; no reason given")
		return nil, err403("forbidden")
	}

	/////////////////////EXTRACT CLIENT PUBKEY /////////////////////
	slog.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)

	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		slog.WarnContext(ctx, "missing clientPublicKey")
		return nil, err400("clientPublicKey failure")
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		return nil, err400("clientPublicKey parse failure")
	}
	// ///////////////////////////////
	// nano header
	// slog.Println(requestBody.KeyAccess.Header)
	// slog.Println(len(requestBody.KeyAccess.Header))
	// s := kaitai.NewStream(bytes.NewReader(requestBody.KeyAccess.Header))
	// n := tdf3.new
	// err = n.Read(s, n, n)
	// if err != nil {
	// 	slog.Panic(err)
	// }
	// slog.Print(n.Header.Length)

	// unwrap using a key from file
	// ciphertext, _ := hex.DecodeString(requestBody.KeyAccess.WrappedKey)
	// symmetricKey, err := tdf3.DecryptWithPrivateKey(requestBody.KeyAccess.WrappedKey, &p.PrivateKey)
	// if err != nil {
	// 	// FIXME handle error
	// 	slog.Panic(err)
	// 	return
	// }

	// ///////////// UNWRAP AND REWRAP //////////////////

	// unwrap using hsm key
	symmetricKey, err := p11.DecryptOAEP(&p.Session, &p.PrivateKey,
		requestBody.KeyAccess.WrappedKey, crypto.SHA1, nil)
	if err != nil {
		slog.WarnContext(ctx, "failure to decrypt dek", "err", err)
		return nil, err400("bad request")
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &clientPublicKey)
	if err != nil {
		slog.WarnContext(ctx, "rewrap: encryptWithPublicKey failed", "err", err, "clientPublicKey", &clientPublicKey)
		return nil, err400("bad key for rewrap")
	}
	// // TODO validate policy
	// TODO: Yikes
	// slog.Println()

	return &RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	}, nil
}

func nanoTDFRewrap(requestBody RequestBody) (*RewrapResponse, error) {
	header := requestBody.KeyAccess.Header

	headerReader := bytes.NewReader(header)

	nanoTDF, err := nanotdf.ReadNanoTDFHeader(headerReader)
	if err != nil {
		slog.Error("Could not fetch attribute definitions from attributes service!", "err", err)
		return nil, err400("parse error")
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), nanoTDF.EphemeralPublicKey.Key)
	if x == nil || y == nil {
		return nil, errors.New("failed to unmarshal ephemeral public key")
	}

	// TODO use PKCS11 instead
	kasEcPrivKeyString := os.Getenv("KAS_EC_SECP256R1_PRIVATE_KEY")
	var ecPrivateRaw []byte

	if strings.Contains(kasEcPrivKeyString, "BEGIN PRIVATE KEY") {
		ecPrivateRaw = []byte(kasEcPrivKeyString)
	} else if strings.Contains(kasEcPrivKeyString, ".pem") {
		// Load PEM file
		ecPrivateRaw, err = os.ReadFile(kasEcPrivKeyString)
		if err != nil {
			return nil, fmt.Errorf("failed to read KAS private key JSON data: %w", err)
		}
	}

	block, _ := pem.Decode(ecPrivateRaw)
	privateKey, err := parsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key to DER: %w", err)
	}

	symmetricKey, err := generateSymmetricKey(nanoTDF.EphemeralPublicKey.Key, privateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Generate a private key
	privateKeyEphemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Extract the public key from the private key
	publicKeyEphemeral := &privateKeyEphemeral.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKeyEphemeral)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
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
		return nil, fmt.Errorf("failed to parse public key PEM block")
	}

	pub, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}
	sessionKey, err := generateSessionKey(pub, privateKeyEphemeral)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	cipherText, err := encryptKey(sessionKey, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	return &RewrapResponse{
		EntityWrappedKey: cipherText,
		SessionPublicKey: pemString,
		SchemaVersion:    schemaVersion,
	}, nil
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
		return nil, fmt.Errorf("error unmarshalling elliptic point")
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
	return nil, fmt.Errorf("failed to parse ec private key")
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
