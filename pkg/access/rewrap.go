package access

import (
	ctx "context"
	"crypto"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"plugin"
	"strings"

	"github.com/opentdf/backend-go/pkg/p11"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"github.com/virtru/access-pdp/attributes"
	"gopkg.in/square/go-jose.v2/jwt"
)

// RewrapRequest HTTP request body in JSON
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
	context := r.Context()
	log := p.Logger
	log.DebugContext(context, "REWRAP", "headers", r.Header, "body", r.Body, "ContentLength", r.ContentLength)

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
			log.ErrorContext(context, "Unable to report Unauthorized", err)
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
			log.ErrorContext(context, "Unable to report invalid auth", err)
			return
		}
		return
	}

	log.DebugContext(context, "Not a 401, probably", "oidcRequestToken", oidcRequestToken)

	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(context, oidcRequestToken)
	if err != nil {
		log.WarnContext(context, "Unable to verify", "err", err)
		panic(err)
	}

	// Extract custom claims
	var claims customClaimsHeader
	if err := idToken.Claims(&claims); err != nil {
		log.WarnContext(context, "Unable to load claims", "err", err)
		panic(err)
	}
	log.DebugContext(context, "verified", "claims", claims)

	//////////////// DECODE REQUEST BODY /////////////////////

	decoder := json.NewDecoder(r.Body)
	var rewrapRequest RewrapRequest
	err = decoder.Decode(&rewrapRequest)
	if err != nil {
		// FIXME handle error. shoudl be 400?
		log.WarnContext(context, "Unable decode rewrap request", "err", err)
		panic(err)
	}
	requestToken, err := jwt.ParseSigned(rewrapRequest.SignedRequestToken)
	if err != nil {
		// FIXME handle error. mabye 400? IDK???
		log.WarnContext(context, "Unable decode parse request", "err", err)
		panic(err)
	}
	var jwtClaimsBody jwt.Claims
	var bodyClaims customClaimsBody
	err = requestToken.UnsafeClaimsWithoutVerification(&jwtClaimsBody, &bodyClaims)
	if err != nil {
		// FIXME handle error
		log.WarnContext(context, "Unable check claims", "err", err)
		panic(err)
	}
	log.DebugContext(context, "okay now we can check", "bodyClaims.RequestBody", bodyClaims.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(bodyClaims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		// FIXME handle error
		log.WarnContext(context, "Unable decode rewrap request", "err", err)
		panic(err)
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		// TODO return 404 or 400
		log.WarnContext(context, "Nano not implemented yet")
		panic("nano not implemented yet")
		// log.Fatal("Nano not implemented yet")
		// return _nano_tdf_rewrap(requestBody, r.Header, claims)
	}

	///////////////////// EXTRACT POLICY /////////////////////
	log.DebugContext(context, "extracting policy", "requestBody.policy", requestBody.Policy)
	// base 64 decode
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy)))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		// FIXME handle error
		log.WarnContext(context, "Unable to decode policy", "err", err)
		panic(err)
	}

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		// logger.Errorf("Could not get namespaces from policy! Error was %s", err)
		log.WarnContext(context, "Could not get namespaces from policy!", "err", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// this part goes in the plugin?
	log.DebugContext(context, "Fetching attributes")

	// Load the plugin
	pl, err := plugin.Open("attributes.so") // Replace with the actual path to your plugin file
	if err != nil {
		log.ErrorContext(context, "Unable to load attributes plugin", "err", err)
		panic(err)
	}
	// Look up the exported function
	fetchAttributesSymbol, err := pl.Lookup("FetchAllAttributes")
	if err != nil {
		log.ErrorContext(context, "Unable to load attributes fetcher function", "err", err)
		panic(err)
	}

	// Assert the symbol to the correct function type
	fetchAttributesFn, ok := fetchAttributesSymbol.(func(ctx.Context, []string) ([]attributes.AttributeDefinition, error))
	if !ok {
		log.ErrorContext(context, "unable to fetch attributes", "err", err)
		panic("unable to fetch attributes")
	}
	// use the module
	definitions, err := fetchAttributesFn(r.Context(), namespaces)
	if err != nil {
		// logger.Errorf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		log.ErrorContext(context, "Could not fetch attribute definitions from attributes service!", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.DebugContext(context, "fetch attributes", "definitions", definitions)

	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(&context, log, claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		// logger.Errorf("Could not perform access decision! Error was %s", err)
		log.WarnContext(context, "Could not perform access decision!", "err", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if !access {
		log.DebugContext(context, "Access Denied")
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	/////////////////////EXTRACT CLIENT PUBKEY /////////////////////
	log.DebugContext(context, "extract public key", "requestBody.ClientPublicKey", requestBody.ClientPublicKey)

	// Decode PEM entity public key
	block, _ := pem.Decode([]byte(requestBody.ClientPublicKey))
	if block == nil {
		// FIXME handle error
		log.DebugContext(context, "err missing clientPublicKey")
		panic("err missing clientPublicKey")
	}
	clientPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// FIXME handle error
		log.DebugContext(context, "parse clientPublicKey fail", "err", err)
		panic(err)
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
		// FIXME handle error
		log.Warn("decrypt wrapped key failed", "err", err)
		panic(err)
	}

	// rewrap
	rewrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &clientPublicKey)
	if err != nil {
		// FIXME handle error
		log.ErrorContext(context, "rewrap: encryptWithPublicKey failed", "err", err)
		panic(err)
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
		log.ErrorContext(context, "rewrap: marshall response failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(responseBytes)
}
