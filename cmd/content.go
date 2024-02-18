/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/arkavo/backend-go/pkg/oidc"
	tdf3 "github.com/arkavo/backend-go/pkg/tdf3/client"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// contentCmd represents the content command
var contentCmd = &cobra.Command{
	Use:   "content",
	Short: "Get the content of a TDF",
	Run:   content,
}

func init() {
	rootCmd.AddCommand(contentCmd)

	// homedir, err := os.UserHomeDir()
	// if err != nil {
	// 	log.Println(err)
	// 	os.Exit(1)
	// }
	// viper.AddConfigPath(fmt.Sprintf("%s/.opentdf", homedir))
	// viper.SetConfigName("config")
	// viper.SetConfigType("toml")

	contentCmd.Flags().String("file", "", "TDF file to extract encrypted payload from")
	contentCmd.Flags().String("output", "stdout", "Where to write the decrypted payload file or stdout")
	contentCmd.Flags().String("output-file", "", "Output file to write decrypted content to")

}

func content(cmd *cobra.Command, _ []string) {
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

	output, err := cmd.Flags().GetString("output")
	if err != nil {
		log.Fatal(err)
	}

	outputFile, err := cmd.Flags().GetString("output-file")
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
	if err != nil {
		log.Fatal(err)
	}
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

	var w io.Writer
	switch output {
	case "stdout":
		w = os.Stdout
	case "file":
		w, err = os.Create(outputFile)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer w.(*os.File).Close()
	start := time.Now()
	size, err := tdf.Stat()
	if err != nil {
		log.Fatal(err)
	}
	err = client.GetContent(tdf, size.Size(), w)
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("\nDecrypted TDF Content in %s\n", duration)
}
