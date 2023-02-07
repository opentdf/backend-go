package access

import (
	// "bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	// "fmt"
	"net/http"
	"strings"
	b64 "encoding/base64"
	// "crypto/rsa"

	// "github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
	// "github.com/opentdf/backend-go/pkg/nano"
	// "github.com/coreos/go-oidc/v3/oidc"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"gopkg.in/square/go-jose.v2/jwt"
	"github.com/opentdf/backend-go/pkg/p11"
	// "golang.org/x/oauth2"
)

// RewrapRequest HTTP request body in JSON
type RewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"`
}

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Entity          Entity         `json:"entity"`
	Policy          string         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
}

type Entity struct {
	Id         string
	Aliases    []string
	Attributes []Attribute
	PublicKey  []byte
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
	EntityID	   string		  `json:"sub"`
	ClientID       string         `json:"clientId"`
	TDFClaims	   ClaimsObject	  `json:"tdf_claims"`
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
	//get the raw token
	oidcRequestToken := r.Header.Get("Authorization")
	splitToken := strings.Split(oidcRequestToken, "Bearer ")
	oidcRequestToken = splitToken[1]
	log.Println(oidcRequestToken)

    // Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(context.Background(), oidcRequestToken)
    if err != nil {
        log.Panic(err)
		return
    }

    // Extract custom claims
    var claims customClaimsHeader
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
	jwt_claims_body := &jwt.Claims{}
	body_claims := &customClaimsBody{}
	err = requestToken.UnsafeClaimsWithoutVerification(jwt_claims_body, body_claims)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	log.Println(body_claims.RequestBody)
	decoder = json.NewDecoder(strings.NewReader(body_claims.RequestBody))
	var requestBody RequestBody
	err = decoder.Decode(&requestBody)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}

	//////////////// FILTER BASED ON ALGORITHM /////////////////////

	if requestBody.Algorithm == "" {
		// log warn
		log.Println("'algorithm' is missing; defaulting to TDF3 rewrap standard, RSA-2048.")
        requestBody.Algorithm = "rsa:2048"
	}

	if requestBody.Algorithm == "ec:secp256r1" {
		log.Fatal("Nano not implemented yet")
		// return _nano_tdf_rewrap(requestBody, r.Header, claims)
	} // else {
	// 	if requestBody.KeyAccess == nil {
	// 		log.Fatalf("Key Access missing from %#v", requestBody)
	// 		// Need to add these custom error types
    //         // raise KeyAccessError("No key access object")
	// 	}
	// 	// return _tdf3_rewrap_v2(dataJson, context, plugin_runner, key_master, claims)
	// }

	///////////////////// EXTRACT POLICY /////////////////////
	log.Println(requestBody.Policy)
	// base 64 decode 
	sDecPolicy, _ := b64.StdEncoding.DecodeString(requestBody.Policy)
	decoder = json.NewDecoder(strings.NewReader(string(sDecPolicy[:])))
	var policy Policy
	err = decoder.Decode(&policy)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
		return
	}
	// ///////////////////////////////

	///////////////////// RETRIEVE ATTR DEFS /////////////////////
	namespaces, err := getNamespacesFromAttributes(policy.Body)
	if err != nil {
		// logger.Errorf("Could not get namespaces from policy! Error was %s", err)
		log.Printf("Could not get namespaces from policy! Error was %s", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	
	// this part goes in the plugin?
	// if len(namespaces) != 0 {
	log.Println("Fetching attributes")
	definitions, err := fetchAttributes(namespaces)
	if err != nil {
		// logger.Errorf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		log.Printf("Could not fetch attribute definitions from attributes service! Error was %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// fetchAttributes(namespaces)
	log.Printf("%+v", definitions)
	// }

	// ///////////////////////////////


	///////////////////// PERFORM ACCESS DECISION /////////////////////

	access, err := canAccess(claims.EntityID, policy, claims.TDFClaims, definitions)

	if err != nil {
		// logger.Errorf("Could not perform access decision! Error was %s", err)
		log.Printf("Could not perform access decision! Error was %s", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if (!access){
		log.Println(errors.New("Not authorized"))
		http.Error(w, "Access Denied", http.StatusForbidden)
		return
	}

	// ///////////////////////////////

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
	//ciphertext, _ := hex.DecodeString(requestBody.KeyAccess.WrappedKey)
	// symmetricKey, err := tdf3.DecryptWithPrivateKey(requestBody.KeyAccess.WrappedKey, &p.PrivateKey)
	// if err != nil {
	// 	// FIXME handle error
	// 	log.Panic(err)
	// 	return
	// }


	// ///////////// UNWRAP AND REWRAP //////////////////
	//unwrap using hsm key
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
		SchemaVersion:    schemaVersion,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(responseBytes)
}
