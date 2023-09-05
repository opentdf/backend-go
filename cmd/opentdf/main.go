package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/opentdf/backend-go/pkg/archive/manifest"
	"github.com/opentdf/backend-go/pkg/tdf3"
	"github.com/opentdf/backend-go/pkg/wellknown"
	"golang.org/x/oauth2/clientcredentials"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	// Define flags for host, clientId, and clientSecret
	host := flag.String("host", "", "Host domain URL where the .well-known/opentdf-configuration")
	clientId := flag.String("clientId", "", "OIDC Client ID for authentication")
	clientSecret := flag.String("clientSecret", "", "OIDC Client secret for authentication")
	flag.Parse()
	log.Printf("Received OpenTDF host URL: %s", *host)
	// get well-known
	wk := strings.TrimSuffix(*host, "/") + "/.well-known/opentdf-configuration"
	log.Printf("Calling %s", wk)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, wk, nil)
	if err != nil {
		log.Println("Error creating request:", err)
		os.Exit(1)
	}
	// Send the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println("Error sending request:", err)
		os.Exit(1)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		os.Exit(1)
	}(resp.Body)
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
	}
	log.Printf("Successful call to %s", wk)
	// parse to opentdf-configuration struct
	var wkTdf wellknown.OpenTdfConfiguration
	err = json.Unmarshal(body, &wkTdf)
	if err != nil {
		log.Println("Error parsing opentdf-configuration:", err)
	}
	log.Printf("Received issuer URL: %s", wkTdf.Issuer)
	// Send request for OIDC Issuer
	log.Printf("Calling %s/.well-known/openid-configuration", strings.TrimSuffix(wkTdf.Issuer, "/"))
	provider, err := oidc.NewProvider(context.Background(), wkTdf.Issuer)
	if err != nil {
		log.Panic(err)
	}
	log.Printf("Received token URL: %s", provider.Endpoint().TokenURL)
	// Create a client key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Panic(err)
	}
	// Derive the public key from the private key.
	publicKey := &privateKey.PublicKey
	// Encode the public key to PEM format
	pubASN1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Println("Error marshalling public key to ASN.1:", err)
	}
	pubBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	}
	publicPEM := pem.EncodeToMemory(pubBlock)
	// Print the keys
	log.Printf("Client Public Key: \n%s\n", publicPEM)
	// Configure an OpenID Connect aware OAuth2 client.
	var verifier *oidc.IDTokenVerifier
	clientConfig := clientcredentials.Config{
		ClientID:       *clientId,
		ClientSecret:   *clientSecret,
		TokenURL:       provider.Endpoint().TokenURL,
		Scopes:         []string{},
		EndpointParams: nil,
		AuthStyle:      0,
	}
	// get access token
	token, err := clientConfig.Token(context.Background())
	if err != nil {
		log.Println("Token failed:", err)
		os.Exit(1)
	}
	log.Printf("Access token: %s", token.AccessToken)
	client := clientConfig.Client(context.Background())
	log.Println("Verifying access token...")
	// verify access token
	oidcConfig := &oidc.Config{
		ClientID:             clientConfig.ClientID,
		SupportedSigningAlgs: nil,
		// no audience set by Cognito, can't find how to set it.  idk why this library checks it
		SkipClientIDCheck:          true,
		SkipExpiryCheck:            false,
		SkipIssuerCheck:            false,
		Now:                        nil,
		InsecureSkipSignatureCheck: false,
	}
	verifier = provider.Verifier(oidcConfig)
	verify, err := verifier.Verify(context.Background(), token.AccessToken)
	if err != nil {
		log.Println("Verify access token failed:", err)
		os.Exit(1)
	}
	log.Printf("Verified access token issued at %v ", verify.IssuedAt)
	// get KAS keys
	log.Printf("Calling %s", wkTdf.JwksUri)
	res, err := client.Get(wkTdf.JwksUri)
	if err != nil {
		log.Println("Error sending request:", err)
		os.Exit(1)
	}
	log.Println(res)
	keySet, err := jwk.ParseReader(res.Body)
	if err != nil {
		log.Println("Error parsing JWK Set:", err)
		os.Exit(1)
	}
	log.Println(keySet)
	key0, ok := keySet.Key(0)
	if !ok {
		log.Println("No key at index 0:", keySet)
		os.Exit(1)
	}
	var kasPublicKeyRsa interface{}
	err = key0.Raw(&kasPublicKeyRsa)
	if err != nil {
		log.Println("Error getting RSA key:", err)
		os.Exit(1)
	}
	// TODO get RSA key
	// TODO create TDF3 with key above
	clearText := "hello world"
	var publicKeyRsa interface{}
	publicKeyRsa = publicKey
	// FIXME IV
	iv := []byte("OEOqJCS6mZsmLWJ3")
	cipherText, err := tdf3.EncryptWithPublicKey([]byte(clearText), &publicKeyRsa)
	if err != nil {
		log.Println("Error encrypting with RSA key:", err)
		os.Exit(1)
	}
	log.Println(hex.EncodeToString(cipherText))
	symmetricKey := []byte("asdasd")
	wrappedKey, err := tdf3.EncryptWithPublicKey(symmetricKey, &kasPublicKeyRsa)
	if err != nil {
		log.Println("Error wrapping with KAS RSA key:", err)
		os.Exit(1)
	}
	wrappedKeyB64 := b64.StdEncoding.EncodeToString(wrappedKey)
	// manifest
	var keyAccess []tdf3.KeyAccess
	keyAccess = append(keyAccess, tdf3.KeyAccess{
		EncryptedMetadata: "",
		PolicyBinding:     "ZGMwNGExZjg0ODFjNDEzZTk5NjdkZmI5MWFjN2Y1MzI0MTliNjM5MmRlMTlhYWM0NjNjN2VjYTVkOTJlODcwNA",
		Protocol:          "kas",
		Type:              "wrapped",
		URL:               "http://localhost:65432/api/kas",
		WrappedKey:        []byte(wrappedKeyB64),
		Header:            nil,
		Algorithm:         "",
	})
	var manifestObject = manifest.Object{
		EncryptionInformation: tdf3.EncryptionInformation{
			IntegrityInformation: tdf3.IntegrityInformation{},
			KeyAccess:            keyAccess,
			Method: tdf3.EncryptionMethod{
				Algorithm:  "AES-256-GCM",
				Streamable: false,
				IV:         iv,
			},
			// FIXME policy
			Policy: "eyJ1dWlkIjoiNjEzMzM0NjYtNGYwYS00YTEyLTk1ZmItYjZkOGJkMGI4YjI2IiwiYm9keSI6eyJhdHRyaWJ1dGVzIjpbXSwiZGlzc2VtIjpbInVzZXJAdmlydHJ1LmNvbSJdfX0",
			Type:   "split",
		},
		Payload: manifest.Payload{
			IsEncrypted: true,
			MimeType:    "text/plain",
			Protocol:    "zip",
			Type:        "reference",
			URL:         "0.payload",
		},
		SchemaVersion: "1.0.0",
	}
	manifestJson, err := json.Marshal(manifestObject)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(manifestJson))
	// Create a new zip archive.
	outFile, err := os.Create("test.tdf.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()
	zipWriter := zip.NewWriter(outFile)
	// Add manifest to the archive
	err = addFileToZip(zipWriter, "0.manifest.json", manifestJson)
	if err != nil {
		log.Fatal(err)
	}
	// Add payload to the archive
	err = addFileToZip(zipWriter, "0.payload", cipherText)
	if err != nil {
		log.Fatal(err)
	}
	// Close the archive
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func addFileToZip(zipWriter *zip.Writer, filename string, contents []byte) error {
	header := zip.FileHeader{
		Name: filename,
		// no need for compression with ciphertext
		Method: zip.Store,
	}
	writer, err := zipWriter.CreateHeader(&header)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, bytes.NewReader(contents))
	return err
}
