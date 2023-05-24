package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDCClient represents the OIDC client
type OIDCClient struct {
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthConfig *oauth2.Config
}

// NewOIDCClient creates a new instance of OIDCClient
func NewOIDCClient(issuerURL, clientID, clientSecret, redirectURL string) (*OIDCClient, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	oauthConfig := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDCClient{
		provider:    provider,
		verifier:    verifier,
		oauthConfig: oauthConfig,
	}, nil
}

// Returns the authentication URL to initiate the OIDC flow
func (c *OIDCClient) GetAuthURL() string {
	return c.oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
}

// Handles the OIDC callback and returns the user details
func (c *OIDCClient) HandleCallback(r *http.Request) (*oidc.IDToken, error) {
	ctx := context.Background()

	oauth2Token, err := c.oauthConfig.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %v", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found in oauth2 token response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %v", err)
	}

	return idToken, nil
}

// Exported symbols
var (
	Client OIDCClient
)

// Plugin initialization
func init() {
	var err error
	Client, err = NewOIDCClient(
		"https://accounts.google.com",
		"your-client-id",
		"your-client-secret",
		"http://localhost:8080/callback",
	)
	if err != nil {
		log.Fatalf("Failed to create OIDC client: %v", err)
	}
}
