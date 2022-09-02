package entitlements

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

type Provider struct {
	OIDCVerifier     *oidc.IDTokenVerifier
	OIDCAuthority    string
	ClientID         string
	OIDCClientSecret string
}

type Definitions struct {
	Groups []string
	// move to other endpoint to get entity specific
	MyGroups []string
}

func (p *Provider) Handler(w http.ResponseWriter, r *http.Request) {
	log.Println("ENTITLEMENTS")
	log.Printf("headers %s", r.Header)
	log.Printf("body %s", r.Body)
	log.Printf("ContentLength %d", r.ContentLength)
	// preflight
	if r.Method == http.MethodOptions {
		return
	}

	//////////////// OIDC VERIFY ///////////////
	//get the raw token
	oidcRequestToken := r.Header.Get("Authorization")
	splitToken := strings.Split(oidcRequestToken, "Bearer ")
	if len(splitToken) > 1 {
		oidcRequestToken = splitToken[1]
	}
	// Parse and verify ID Token payload.
	idToken, err := p.OIDCVerifier.Verify(context.Background(), oidcRequestToken)
	if err != nil {
		log.Println(err)
		// FIXME microsoft uses two authorities, skip this check
		//w.WriteHeader(http.StatusForbidden)
		//return
	}
	log.Println(idToken)

	// Initializing the client credential
	cred, err := confidential.NewCredFromSecret(p.OIDCClientSecret)
	if err != nil {
		log.Panic("could not create a cred from a secret: %w", err)
	}
	confidentialClientApp, err := confidential.New(p.ClientID, cred, confidential.WithAuthority(p.OIDCAuthority))
	log.Println(confidentialClientApp)
	credential, err := confidentialClientApp.AcquireTokenByCredential(r.Context(), []string{"https://graph.microsoft.com/.default"})
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println(credential)

	// msgraphsdk
	auth := authentication.NewBaseBearerTokenAuthenticationProvider(&MsalAccessTokenProvider{
		AccessToken: credential.AccessToken,
	})
	adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
	if err != nil {
		fmt.Printf("Error creating adapter: %v\n", err)
		return
	}
	client := msgraphsdk.NewGraphServiceClient(adapter)
	log.Println(client)
	// organization groups
	groups, err := client.Groups().Get()
	if err != nil {
		log.Panic(err)
		return
	}
	var groupsArray []string
	for _, groupable := range groups.GetValue() {
		groupsArray = append(groupsArray, *groupable.GetDisplayName())
	}
	// my groups

	responseBytes, err := json.Marshal(&Definitions{
		Groups: groupsArray,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
	_, _ = w.Write(responseBytes)
}

type MsalAccessTokenProvider struct {
	AccessToken string
}

// GetAuthorizationToken returns the access token. ignores the provided url.
func (p *MsalAccessTokenProvider) GetAuthorizationToken(url *url.URL, additionalAuthenticationContext map[string]interface{}) (string, error) {
	return p.AccessToken, nil
}

// GetAllowedHostsValidator returns nil
func (p *MsalAccessTokenProvider) GetAllowedHostsValidator() *authentication.AllowedHostsValidator {
	return nil
}
