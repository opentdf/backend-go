package access

import (
	"crypto"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	log := p.Logger
	log.DebugContext(ctx, "REWRAP", "headers", r.Header, "body", r.Body, "ContentLength", r.ContentLength)

	// preflight
	if r.ContentLength == 0 {
		// TODO: What is this doing here?
		// If there is an empty body, should we return 400?
		return
	}

	//////////////// OIDC VERIFY ///////////////
	// Check if Authorization header is present
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.InfoContext(ctx, "no authorization header")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Extract OIDC token from the Authorization header
	oidcRequestToken := strings.TrimPrefix(authHeader, "Bearer ")
	if oidcRequestToken == authHeader {
		log.InfoContext(ctx, "bearer token missing prefix")
		http.Error(w, "invalid authorization header format", http.StatusBadRequest)
		return
	}
	log.DebugContext(ctx, "not a 401, probably", "oidcRequestToken", oidcRequestToken)

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(ctx, oidcRequestToken)
	if err != nil {
		http.Error(w, "forbidden", http.StatusBadRequest)
		log.WarnContext(ctx, "Unable to verify", "err", err)
		return
	}

	if !strings.HasPrefix(os.Getenv("OIDC_ISSUER"), idToken.Issuer) {
		http.Error(w, "forbidden", http.StatusForbidden)
		log.WarnContext(ctx, "Invalid token issuer", "issuer", idToken.Issuer)
		return
	}

	// Extract custom claims
	var claims customClaimsHeader
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		log.WarnContext(ctx, "unable to load claims", "err", err)
		return
	}
	log.DebugContext(ctx, "verified", "claims", claims)

	//////////////// DECODE REQUEST BODY /////////////////////

	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err = decoder.Decode(&rewrapRequest)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		log.WarnContext(ctx, "unable decode rewrap request", "err", err)
		return
	}
	requestToken, err := jwt.ParseSigned(rewrapRequest.SignedRequestToken)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		log.WarnContext(ctx, "unable parse request", "err", err)
		return
	}
	var jwtClaimsBody jwt.Claims
	var bodyClaims customClaimsBody
	err = requestToken.UnsafeClaimsWithoutVerification(&jwtClaimsBody, &bodyClaims)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		log.WarnContext(ctx, "unable decode request", "err", err)
		return
	}
	log.DebugContext(ctx, "okay now we can check", "bodyClaims.RequestBody", bodyClaims.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		log.WarnContext(ctx, "unable decode request body", "err", err)
		return
	}

	if !strings.HasPrefix(os.Getenv("OIDC_ISSUER"), requestBody.KeyAccess.URL) {
		http.Error(w, "forbidden", http.StatusForbidden)
		log.WarnContext(ctx, "invalid key access url", "keyAccessURL", requestBody.KeyAccess.URL)
		return
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		http.Error(w, "Unsupported Algorithm", http.StatusBadRequest)
		log.WarnContext(ctx, "Nano not implemented yet")
		return
	}

	///////////////////// EXTRACT POLICY /////////////////////
	log.DebugContext(ctx, "extracting policy", "requestBody.policy", requestBody.Policy)
	// base 64 decode
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		http.Error(w, "Invalid policy", http.StatusBadRequest)
		log.WarnContext(ctx, "unable to decode policy", "err", err)
		return
	}

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		http.Error(w, "Access Denied", http.StatusForbidden)
		log.WarnContext(ctx, "Could not get namespaces from policy!", "err", err)
		return
	}

	// this part goes in the plugin?
	log.DebugContext(ctx, "Fetching attributes")
	definitions, err := fetchAttributes(ctx, namespaces)
	if err != nil {
		// logger.Errorf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		log.ErrorContext(ctx, "Could not fetch attribute definitions from attributes service!", "err", err)
		http.Error(w, "attribute server request failure", http.StatusInternalServerError)
		return
	}
	log.DebugContext(ctx, "fetch attributes", "definitions", definitions)

	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(&ctx, claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		// logger.Errorf("Could not perform access decision! Error was %s", err)
		log.WarnContext(ctx, "Could not perform access decision!", "err", err)
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	if !access {
		log.WarnContext(ctx, "Access Denied; no reason given")
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	/////////////////////EXTRACT CLIENT PUBKEY /////////////////////
	log.DebugContext(ctx, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)

	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		log.WarnContext(ctx, "missing clientPublicKey")
		http.Error(w, "clientPublicKey failure", http.StatusBadRequest)
		return
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.WarnContext(ctx, "failure to parse clientPublicKey", "err", err)
		http.Error(w, "clientPublicKey parse failure", http.StatusBadRequest)
		return
	}
	// ///////////////////////////////

	// nano header
	// log.Println(requestBody.KeyAccess.Header)
	// log.Println(len(requestBody.KeyAccess.Header))
	// s := kaitai.NewStream(bytes.NewReader(requestBody.KeyAccess.Header))
	// n := tdf3.new
	// err = n.Read(s, n, n)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// log.Print(n.Header.Length)

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
		log.WarnContext(ctx, "failure to decrypt dek", "err", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &clientPublicKey)
	if err != nil {
		log.WarnContext(ctx, "rewrap: encryptWithPublicKey failed", "err", err, "clientPublicKey", &clientPublicKey)
		http.Error(w, "bad key for rewrap", http.StatusBadRequest)
		return
	}
	// // TODO validate policy
	// TODO: Yikes
	// log.Println()

	// // TODO store policy
	// rewrappedKey := []byte("TODO")
	responseBytes, err := json.Marshal(&RewrapResponse{
		EntityWrappedKey: rewrappedKey,
		SessionPublicKey: "",
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		log.ErrorContext(ctx, "rewrap: marshall response failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_, err = w.Write(responseBytes)
	if err != nil {
		// FIXME Yikes what can we do?
		log.ErrorContext(ctx, "rewrap: marshall response failed", "err", err)
	}
}
