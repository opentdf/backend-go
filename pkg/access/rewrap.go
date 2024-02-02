package access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/opentdf/backend-go/pkg/nanotdf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/opentdf/backend-go/pkg/p11"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

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

func legacyBearerToken(ctx context.Context, newBearer string) (string, error) {
	if newBearer != "" {
		// token found in request body
		return newBearer, nil
	}
	slog.DebugContext(ctx, "Bearer not set; investigating authorization header")
	// Check for bearer token in Authorization header
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		slog.InfoContext(ctx, "no authorization header")
		return "", err401("no auth token")
	}
	authHeaders := md.Get("Authorization")
	if len(authHeaders) == 0 {
		slog.InfoContext(ctx, "no authorization header")
		return "", err401("no auth token")
	}
	if len(authHeaders) != 1 {
		slog.InfoContext(ctx, "authorization header repetition")
		return "", err401("auth fail")
	}

	bearer := strings.TrimPrefix(authHeaders[0], "Bearer ")
	if bearer == authHeaders[0] || len(bearer) < 1 {
		slog.InfoContext(ctx, "bearer token missing prefix")
		return "", err401("auth fail")
	}

	return bearer, nil
}

func generateHMACDigest(ctx context.Context, msg, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(msg)
	if err != nil {
		slog.WarnContext(ctx, "failed to compute hmac")
		return nil, errors.Join(ErrUser, status.Error(codes.InvalidArgument, "policy hmac"))
	}
	return mac.Sum(nil), nil
}

func (p *Provider) verifyBearerAndParseRequestBody(ctx context.Context, in *RewrapRequest) (*rsa.PublicKey, *RequestBody, error) {
	idToken, err := p.OIDCVerifier.Verify(ctx, in.Bearer)
	if err != nil {
		slog.WarnContext(ctx, "unable verify bearer token", "err", err, "bearer", in.Bearer, "oidc", p.OIDCVerifier)
		return nil, nil, err403("403")
	}

	var cl customClaimsHeader
	err = idToken.Claims(&cl)
	if err != nil {
		slog.WarnContext(ctx, "unable parse claims", "err", err)
		return nil, nil, err403("403")
	}

	block, _ := pem.Decode([]byte(cl.TDFClaims.ClientPublicSigningKey))
	if block == nil {
		slog.WarnContext(ctx, "missing clientPublicSigningKey")
		return nil, nil, err403("token missing PoP")
	}
	clientSigningPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.WarnContext(ctx, "failure to parse clientSigningPublicKey", "err", err)
		return nil, nil, err403("signing key parse failure")
	}
	pubSigner, ok := clientSigningPublicKey.(*rsa.PublicKey)
	if !ok {
		slog.WarnContext(ctx, fmt.Sprintf("signer not an RSA key, was [%T]", clientSigningPublicKey))
		return nil, nil, err400("signer unsupported type")
	}

	requestToken, err := jwt.ParseSigned(in.SignedRequestToken)
	if err != nil {
		slog.WarnContext(ctx, "unable parse request", "err", err)
		return nil, nil, err400("bad request")
	}
	var bodyClaims customClaimsBody
	err = requestToken.Claims(pubSigner, &bodyClaims)
	if err != nil {
		slog.WarnContext(ctx, "unable decode request", "err", err)
		return nil, nil, err400("bad request")
	}
	slog.DebugContext(ctx, "okay now we can check", "bodyClaims.RequestBody", bodyClaims.RequestBody)
	decoder := json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		slog.WarnContext(ctx, "unable decode request body", "err", err)
		return nil, nil, err400("bad request")
	}

	// Decode PEM entity public key
	block, _ = pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		slog.WarnContext(ctx, "missing clientPublicKey")
		return nil, nil, err400("clientPublicKey failure")
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		return nil, nil, err400("clientPublicKey parse failure")
	}
	pub, ok := clientPublicKey.(*rsa.PublicKey)
	if !ok {
		slog.WarnContext(ctx, fmt.Sprintf("clientPublicKey not an RSA key, was [%T]", clientPublicKey))
		return nil, nil, err400("clientPublicKey unsupported type")
	}

	return pub, &requestBody, nil
}

func (p *Provider) verifyAndParsePolicy(ctx context.Context, requestBody *RequestBody, k []byte) (*Policy, error) {
	actualHMAC, err := generateHMACDigest(context.Background(), []byte(requestBody.Policy), k)
	if err != nil {
		slog.WarnContext(ctx, "unable to generate policy hmac", "err", err)
		return nil, err400("bad request")
	}
	expectedHMAC := make([]byte, base64.StdEncoding.DecodedLen(len(requestBody.KeyAccess.PolicyBinding)))
	n, err := base64.StdEncoding.Decode(expectedHMAC, []byte(requestBody.KeyAccess.PolicyBinding))
	expectedHMAC = expectedHMAC[:n]
	slog.InfoContext(ctx, "policy hmac mismatch", "actual", actualHMAC, "expected", expectedHMAC)
	if err != nil {
		slog.WarnContext(ctx, "invalid policy binding", "err", err)
		return nil, err400("bad request")
	}
	if !hmac.Equal(actualHMAC, expectedHMAC) {
		slog.WarnContext(ctx, "policy hmac mismatch", "actual", actualHMAC, "expected", expectedHMAC)
		return nil, err400("bad request")
	}
	sDecPolicy, err := base64.StdEncoding.DecodeString(requestBody.Policy)
	if err != nil {
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		slog.WarnContext(ctx, "unable to decode policy", "err", err)
		return nil, err400("bad request")
	}
	return &policy, nil
}

func (p *Provider) Rewrap(ctx context.Context, in *RewrapRequest) (*RewrapResponse, error) {
	slog.DebugContext(ctx, "REWRAP")

	bearer, err := legacyBearerToken(ctx, in.Bearer)
	if err != nil {
		return nil, err
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

	clientPublicKey, requestBody, err := p.verifyBearerAndParseRequestBody(ctx, in)
	if err != nil {
		return nil, err
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
		return nanoTDFRewrap(*requestBody, &p.Session, &p.PrivateKeyEC)
	}

	slog.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)

	symmetricKey, err := p11.DecryptOAEP(&p.Session, &p.PrivateKey,
		requestBody.KeyAccess.WrappedKey, crypto.SHA1, nil)
	if err != nil {
		slog.WarnContext(ctx, "failure to decrypt dek", "err", err)
		return nil, err400("bad request")
	}

	slog.DebugContext(ctx, "verifying policy binding", "requestBody.policy", requestBody.Policy)
	policy, err := p.verifyAndParsePolicy(ctx, requestBody, symmetricKey)
	if err != nil {
		return nil, err
	}

	slog.DebugContext(ctx, "extracting policy", "requestBody.policy", requestBody.Policy)
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		slog.WarnContext(ctx, "Could not get namespaces from policy!", "err", err)
		return nil, err403("forbidden")
	}

	slog.DebugContext(ctx, "Fetching attributes", "policy.namespaces", namespaces, "policy.body", policy.Body)
	definitions, err := p.fetchAttributes(ctx, namespaces)
	if err != nil {
		slog.ErrorContext(ctx, "Could not fetch attribute definitions from attributes service!", "err", err)
		return nil, err503("attribute server request failure")
	}
	slog.DebugContext(ctx, "fetch attributes", "definitions", definitions)

	access, err := canAccess(ctx, claims.EntityID, *policy, claims.TDFClaims, definitions)

	if err != nil {
		slog.WarnContext(ctx, "Could not perform access decision!", "err", err)
		return nil, err403("forbidden")
	}

	if !access {
		slog.WarnContext(ctx, "Access Denied; no reason given")
		return nil, err403("forbidden")
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, clientPublicKey)
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

func nanoTDFRewrap(requestBody RequestBody, session *p11.Pkcs11Session, key *p11.Pkcs11PrivateKeyEC) (*RewrapResponse, error) {
	headerReader := bytes.NewReader(requestBody.KeyAccess.Header)

	header, err := nanotdf.ReadNanoTDFHeader(headerReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NanoTDF header: %w", err)
	}

	symmetricKey, err := p11.GenerateNanoTDFSymmetricKey(header.EphemeralPublicKey.Key, session, key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	clientPublicKey := requestBody.ClientPublicKey
	block, _ := pem.Decode([]byte(clientPublicKey))
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

	// Convert public key to 65-bytes format
	pubKeyBytes := make([]byte, 1+len(pub.X.Bytes())+len(pub.Y.Bytes()))
	pubKeyBytes[0] = 0x4 // ID for uncompressed format
	if copy(pubKeyBytes[1:33], pub.X.Bytes()) != 32 || copy(pubKeyBytes[33:], pub.Y.Bytes()) != 32 {
		return nil, fmt.Errorf("failed to serialize keypair: %v", pub)
	}

	privateKeyHandle, publicKeyHandle, err := p11.GenerateEphemeralKasKeys(session)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keypair: %w", err)
	}
	sessionKey, err := p11.GenerateNanoTDFSessionKey(session, privateKeyHandle, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session key: %w", err)
	}

	cipherText, err := wrapKeyAES(sessionKey, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	// see explanation why Public Key starts at position 2
	//https://github.com/wqx0532/hyperledger-fabric-gm-1/blob/master/bccsp/pkcs11/pkcs11.go#L480
	pubGoKey, err := ecdh.P256().NewPublicKey(publicKeyHandle[2:])
	if err != nil {
		return nil, fmt.Errorf("failed to make public key") // Handle error, e.g., invalid public key format
	}

	pbk, err := x509.MarshalPKIXPublicKey(pubGoKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public Key to PKIX")
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pbk,
	}
	pemString := string(pem.EncodeToMemory(pemBlock))

	return &RewrapResponse{
		EntityWrappedKey: cipherText,
		SessionPublicKey: pemString,
		SchemaVersion:    schemaVersion,
	}, nil
}

func wrapKeyAES(sessionKey, dek []byte) ([]byte, error) {
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

	cipherText := aesGcm.Seal(iv, iv, dek, nil)
	return cipherText, nil
}
