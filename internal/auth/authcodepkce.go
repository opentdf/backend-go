package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/oauth2"
)

type AuthorizaionCodePKCE struct {
	Oauth2Config *oauth2.Config
	Tokens       *oauth2.Token
	PublicKey    []byte
}

type OpenTdfTokenSource struct {
	OpenTdfToken *oauth2.Token
}

func (acp *AuthorizaionCodePKCE) Login() (*oauth2.Token, error) {
	var (
		tokens *oauth2.Token
	)
	// Configure the OAuth2 client.
	// conf := &oauth2.Config{
	// 	ClientID:    acp.ClientID, //"52HgtF4HBt4I1SOyJNEhvF3Vwpw7F8VP",
	// 	Scopes:      []string{"openid", "profile", "email"},
	// 	RedirectURL: "http://localhost:3000/callback", //"http://localhost:8081/callback",
	// 	Endpoint: oauth2.Endpoint{
	// 		AuthURL:  "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/auth",  //"https://dev-yzqjwcakzru3kxes.us.auth0.com/authorize",
	// 		TokenURL: "https://platform.virtru.us/auth/realms/tdf/protocol/openid-connect/token", //"https://dev-yzqjwcakzru3kxes.us.auth0.com/oauth/token",
	// 	},
	// }

	conf := acp.Oauth2Config

	// Create a HTTP server to handle the callback ":3000"
	srv := &http.Server{Addr: ":3000"}
	stop := make(chan os.Signal, 1)

	// Generate a code verifier and code challenge.
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %v", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Start a web server to handle the OAuth2 callback.
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Get the authorization code from the query parameters.
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}

		// Exchange the authorization code for an access token.
		token, err := conf.Exchange(context.Background(), code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange authorization code: %v", err), http.StatusInternalServerError)
			return
		}

		// Build PoP Request with refresh token to get tdf_claims in jwt
		formBody := bytes.NewBufferString(fmt.Sprintf("grant_type=refresh_token&refresh_token=%s&client_id=%s", token.RefreshToken, acp.Oauth2Config.ClientID))
		req, err := http.NewRequest(http.MethodPost, acp.Oauth2Config.Endpoint.TokenURL, formBody)
		if err != nil {
			return
		}
		req.Header.Set("X-VirtruPubKey", base64.StdEncoding.EncodeToString(acp.PublicKey))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Error getting token: %v\n", err)
		}
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&tokens)
		if err != nil {
			log.Fatalf("Error decoding token: %v\n", err)
		}
		// Write the user info to the response.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("Return to the CLI to continue.")

		// Send a value to the stop channel to simulate the SIGINT signal.
		stop <- syscall.SIGINT
	})
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("code_challenge", challenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"), oauth2.SetAuthURLParam("audience", "https://dev-yzqjwcakzru3kxes.us.auth0.com/api/v2/"))
	fmt.Println(url)
	openBrowser(url)

	// Start the HTTP server in a separate goroutine.
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for a SIGINT or SIGTERM signal to shutdown the server.
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down HTTP server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Failed to shutdown HTTP server gracefully: %v", err)
		return nil, err
	}
	acp.Tokens = tokens
	return tokens, nil
}

func (acp *AuthorizaionCodePKCE) Client() (*http.Client, error) {
	tokens, err := acp.Oauth2Config.TokenSource(context.Background(), acp.Tokens).Token()
	if err != nil {
		return nil, err
	}
	return acp.Oauth2Config.Client(context.Background(), tokens), nil
}

func openBrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		return fmt.Errorf("failed to open browser: %v", err)
	}

	return nil
}

func generateCodeVerifier() (string, error) {
	const codeVerifierLength = 32 // You can adjust the length of the code verifier as needed
	randomBytes := make([]byte, codeVerifierLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate code verifier: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (ots *OpenTdfTokenSource) Token() (*oauth2.Token, error) {
	return ots.OpenTdfToken, nil
}
