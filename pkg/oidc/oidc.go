package oidc

import (
	"fmt"
	"net/http"

	"github.com/goccy/go-json"
	"github.com/opentdf/backend-go/internal/auth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type OidcConfig struct {
	ClientID          string
	ClientSecret      string
	DiscoveryEndpoint string
	PublicKey         []byte
	Tokens            *oauth2.Token
}

type Client interface {
	Login() (*oauth2.Token, error)
	Client() (*http.Client, error)
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func NewOidcClient(conf OidcConfig) (Client, error) {
	var (
		client Client
		err    error
	)
	endpoints, err := discoverEndpoints(conf.DiscoveryEndpoint)
	if err != nil {
		return nil, err
	}

	if conf.ClientSecret != "" {
		client = &auth.ClientCredentials{
			Config: &clientcredentials.Config{
				ClientID:     conf.ClientID,
				ClientSecret: conf.ClientSecret,
				Scopes:       []string{"openid", "profile", "email"},
				TokenURL:     endpoints.TokenURL,
			},
			PublicKey: conf.PublicKey,
			Tokens:    conf.Tokens,
		}
	} else {
		client = &auth.AuthorizaionCodePKCE{
			Oauth2Config: &oauth2.Config{
				ClientID:    conf.ClientID,
				Scopes:      []string{"openid", "profile", "email"},
				RedirectURL: "http://localhost:3000/callback",
				Endpoint:    *endpoints,
			},
			PublicKey: conf.PublicKey,
			Tokens:    conf.Tokens,
		}
	}
	return client, nil
}

func discoverEndpoints(wellKnown string) (*oauth2.Endpoint, error) {
	var (
		d         = new(discovery)
		endpoints = new(oauth2.Endpoint)
	)
	req, err := http.NewRequest(http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("could get discovery endpoint: %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(d)
	if err != nil {
		return nil, err
	}
	endpoints.AuthURL = d.AuthorizationEndpoint
	endpoints.TokenURL = d.TokenEndpoint
	return endpoints, nil

}
