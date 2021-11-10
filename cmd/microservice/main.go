package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v4"
	"github.com/opentdf/backend-go/pkg/access"
	"golang.org/x/oauth2"
)

const kasName = "access-provider-000"
const hostname = "localhost"

func main() {
	kasURI, _ := url.Parse("https://" + hostname + ":5000")
	kas := access.Provider{
		URI:         *kasURI,
		PrivateKey:  getPrivateKey(kasName),
		Certificate: x509.Certificate{},
		Attributes:  nil,
	}
	// OIDC
	provider, err := oidc.NewProvider(context.Background(), "https://accounts.google.com")
	if err != nil {
		// handle error
	}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "",
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}
	log.Println(oauth2Config)
	// Open up our database connection.
	config, err := pgx.ParseConfig("postgres://host:5432/database?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	config.Host = os.Getenv("POSTGRES_HOST")
	config.Database = os.Getenv("POSTGRES_DATABASE")
	config.User = os.Getenv("POSTGRES_USER")
	config.Password = "mysecretpassword"
	config.LogLevel = pgx.LogLevelTrace
	conn, err := pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal(err)
	}
	//defer the close till after the main function has finished	executing
	defer conn.Close(context.Background())
	var greeting string
	//
	conn.QueryRow(context.Background(), "select 1").Scan(&greeting)
	fmt.Println(greeting)

	// os interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	// server
	server := http.Server{
		Addr:         "0.0.0.0:8080",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	http.HandleFunc("/rewrap", kas.Handler)
	go func() {
		log.Printf("listening on http://%s", server.Addr)
		log.Printf(os.Getenv("SERVICE"))
		if err := server.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	<-stop
	err = server.Shutdown(context.Background())
	if err != nil {
		log.Println(err)
	}
}

func getPrivateKey(name string) rsa.PrivateKey {
	fileBytes := loadBytes(name + "-private.pem")
	block, _ := pem.Decode(fileBytes)
	if block == nil {
		log.Panic("empty block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panic(err)
	}
	return *privateKey
}

func loadBytes(name string) []byte {
	pk := os.Getenv("PRIVATE_KEY")
	if pk != "" {
		return []byte(pk)
	}
	path := filepath.Join("testdata", name) // relative path
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic(err)
	}
	return fileBytes
}
