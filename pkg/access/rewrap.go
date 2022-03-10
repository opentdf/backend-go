package access

import (
	// "bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	// "fmt"
	"net/http"
	"strings"
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


	//////////////// DECODE BODY EXTRACT CLIENT PUBKEY /////////////////////
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
