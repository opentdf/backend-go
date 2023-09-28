package auth

import (
	"context"
	"encoding/base64"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type ClientCredentials struct {
	Config    *clientcredentials.Config
	Tokens    *oauth2.Token
	PublicKey []byte
}

func (cc *ClientCredentials) Login() (*oauth2.Token, error) {
	hc := &http.Client{Transport: &clientCredientialFlowCustomTransport{PublicKey: cc.PublicKey}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, hc)

	tokens, err := cc.Config.Token(ctx)
	if err != nil {
		return nil, err
	}
	return tokens, nil

}

func (cc *ClientCredentials) Client() (*http.Client, error) {
	hc := &http.Client{Transport: &clientCredientialFlowCustomTransport{PublicKey: cc.PublicKey}}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, hc)

	_, err := cc.Config.Token(ctx)
	if err != nil {
		return nil, err
	}
	return cc.Config.Client(ctx), nil
}

type clientCredientialFlowCustomTransport struct {
	PublicKey []byte
}

func (t *clientCredientialFlowCustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {

	// Set X-VirtruPubKey header
	req.Header.Set("X-VirtruPubKey", base64.StdEncoding.EncodeToString(t.PublicKey))

	// Call default rounttrip
	response, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// return result of default roundtrip
	return response, err
}
