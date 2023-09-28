/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/opentdf/backend-go/pkg/oidc"
	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// metadataCmd represents the metadata command
var metadataCmd = &cobra.Command{
	Use:   "metadata",
	Short: "Get Encrypted Metadata",
	Run:   metadata,
}

func init() {
	rootCmd.AddCommand(metadataCmd)

	metadataCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")

}

func metadata(cmd *cobra.Command, _ []string) {
	var (
		opentdfCredentials OpenTDFCredentials
		oauth2Client       *http.Client
	)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	byteCredentials, err := os.ReadFile(fmt.Sprintf("%s/.opentdf/credentials.toml", homedir))
	if err != nil {
		log.Fatal(err)
	}
	if err = toml.Unmarshal(byteCredentials, &opentdfCredentials); err != nil {
		log.Fatal(err)
	}

	oidcDiscoveryEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcdiscoveryendpoint", opentdfCredentials.Profile))
	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", opentdfCredentials.Profile))
	clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", opentdfCredentials.Profile))
	oClient, err := oidc.NewOidcClient(oidc.OidcConfig{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		DiscoveryEndpoint: oidcDiscoveryEndpoint,
		PublicKey:         opentdfCredentials.PublicKey,
		Tokens:            opentdfCredentials.Tokens,
	})
	oauth2Client, err = oClient.Client()
	if err != nil {
		log.Fatal(err)
	}
	kasEndpoint := viper.GetStringSlice(fmt.Sprintf("profiles.%s.kasendpoint", opentdfCredentials.Profile))

	client, err := tdf3.NewTDFClient(tdf3.TDFClientOptions{
		KasEndpoint: kasEndpoint,
		HttpClient:  oauth2Client,
		PrivKey:     opentdfCredentials.PrivateKey,
		PubKey:      opentdfCredentials.PublicKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	tdf, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	size, err := tdf.Stat()
	if err != nil {
		log.Fatal(err)
	}
	metadata, err := client.GetEncryptedMetaData(tdf, size.Size())
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("Decrypted TDF Encrypted Metadata in %s\n", duration)
	fmt.Printf("Encrypted Metadata: %s\n", metadata)
}
