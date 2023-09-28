package kas

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/pkg/tdf3"
)

const (
	kasPubKeyEndpoint = "/kas_public_key"
)

type Client struct {
	*http.Client
	Endpoint *url.URL
}

type KasClientOptions struct {
	HttpClient *http.Client
	Endpoint   *url.URL
}

type RewrapRequest struct {
	SignedRequestToken string `json:"signedRequestToken"`
}

type RequestBody struct {
	AuthToken       string         `json:"authToken"`
	KeyAccess       tdf3.KeyAccess `json:"keyAccess"`
	Policy          []byte         `json:"policy,omitempty"`
	Algorithm       string         `json:"algorithm,omitempty"`
	ClientPublicKey string         `json:"clientPublicKey"`
	SchemaVersion   string         `json:"schemaVersion,omitempty"`
}

type RewrapResponse struct {
	EntityWrappedKey []byte `json:"entityWrappedKey"`
	SessionPublicKey string `json:"sessionPublicKey"`
	SchemaVersion    string `json:"schemaVersion,omitempty"`
}

func NewClient(ops ...KasClientOptions) (*Client, error) {
	client := &Client{}
	if len(ops) > 0 {
		if ops[0].HttpClient == nil {
			return nil, errors.New("http client cannot be nil. use golang oauth2 package to create an http client")
		}
		client.Client = ops[0].HttpClient
		if ops[0].Endpoint != nil && ops[0].Endpoint.String() != "" {
			client.Endpoint = ops[0].Endpoint
		}
	}
	clientDefaults(client)
	return client, nil
}

func clientDefaults(client *Client) {

}

func (c *Client) LocalRewrap(msg []byte) ([]byte, error) {
	// Fetch remote public key
	endpoint := fmt.Sprintf("%s%s", c.Endpoint.String(), kasPubKeyEndpoint)
	req, _ := http.NewRequest("GET", endpoint, nil)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var key string
	err = json.NewDecoder(resp.Body).Decode(&key)

	if err != nil {
		return nil, errors.Join(err, errors.New("unable to decode kas public key"))
	}
	// Get Public Key
	pubKey, err := tdfCrypto.ParsePublicKey([]byte(key))
	if err != nil {
		return nil, errors.Join(err, errors.New("unable to parse public key"))
	}
	return c.Rewrap(pubKey, msg)
}

func (c *Client) Rewrap(key *x509.Certificate, msg []byte) ([]byte, error) {
	wrappedKey, err := tdfCrypto.EncryptOAEP(key.PublicKey.(*rsa.PublicKey), msg)
	if err != nil {
		return nil, err
	}
	return wrappedKey, nil
}

func (c *Client) RemoteRewrap(rr *RequestBody, key any) (*RewrapResponse, error) {
	var (
		rewrapResponse = new(RewrapResponse)
	)

	rewrapRewToSign, err := json.Marshal(rr)
	if err != nil {
		return nil, err
	}

	signedRequest, err := signRewrapRequest(rewrapRewToSign, key)
	if err != nil {
		return nil, err
	}

	signedRequestToken := &RewrapRequest{SignedRequestToken: string(signedRequest)}
	jsonBody, err := json.Marshal(signedRequestToken)
	if err != nil {
		return nil, err
	}
	reqBody := bytes.NewReader(jsonBody)

	// This needs to be changed to grab tdf from keyaccess
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s", c.Endpoint.String(), "v2/rewrap"), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if err != nil {
			return nil, err
		}
		errBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("rewrap failed with status code: %d body: %s", resp.StatusCode, string(errBody))
	}

	err = json.NewDecoder(resp.Body).Decode(&rewrapResponse)
	if err != nil {
		return nil, err
	}
	return rewrapResponse, nil
}

func signRewrapRequest(rr []byte, key any) ([]byte, error) {
	requestBody := jwt.New()
	requestBody.Set("exp", time.Now().Add(time.Minute*5).Unix())
	requestBody.Set("requestBody", string(rr))
	return jwt.Sign(requestBody, jwt.WithKey(jwa.RS256, key))
}
