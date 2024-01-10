package access

import (
	"crypto"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
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
		http.Error(w, "Unsupported Algorithm", http.StatusBadRequest)
		slog.WarnContext(ctx, "Nano not implemented yet")
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
