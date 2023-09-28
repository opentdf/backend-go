/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tdfCrypto "github.com/opentdf/backend-go/internal/crypto"
	"github.com/opentdf/backend-go/pkg/oidc"
	"golang.org/x/oauth2"
)

type OpenTDFCredentials struct {
	Profile    string        `toml:"profile"`
	Tokens     *oauth2.Token `toml:"tokens"`
	PrivateKey []byte        `toml:"privateKey"`
	PublicKey  []byte        `toml:"publicKey"`
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to your OpenTDF Environment",
	Run:   login,
}

func init() {
	rootCmd.AddCommand(loginCmd)

	viper.AddConfigPath("$HOME/.opentdf")
	viper.SetConfigName("config")
	viper.SetConfigType("toml")

	loginCmd.Flags().String("client-id", "", "Client ID")
	loginCmd.Flags().String("client-secret", "", "Client Secret")
	loginCmd.Flags().String("oidc-endpoint", "", "OIDC Endpoint")
	loginCmd.Flags().String("profile", "default", "Profile to use")

	viper.BindPFlag("clientid", loginCmd.Flags().Lookup("client-id"))
	viper.BindPFlag("clientsecret", loginCmd.Flags().Lookup("client-secret"))
	viper.BindPFlag("oidcendpoint", loginCmd.Flags().Lookup("oidc-endpoint"))

}

func login(cmd *cobra.Command, args []string) {
	var (
		err                error
		opentdfCredentials OpenTDFCredentials
	)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		log.Fatal(err)
	}

	opentdfCredentials.Profile = profile

	clientID := viper.GetString(fmt.Sprintf("profiles.%s.clientid", profile))
	clientSecret := viper.GetString(fmt.Sprintf("profiles.%s.clientsecret", profile))
	oidcDiscoveryEndpoint := viper.GetString(fmt.Sprintf("profiles.%s.oidcdiscoveryendpoint", profile))

	if err != nil {
		log.Fatal("could not discover oidc endpoints : ", err)
	}

	opentdfCredentials.PrivateKey, opentdfCredentials.PublicKey, err = tdfCrypto.GenerateRSAKeysPem(2048)
	if err != nil {
		log.Fatalf("Error generating RSA keys: %v\n", err)
	}

	oClient, err := oidc.NewOidcClient(oidc.OidcConfig{
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		DiscoveryEndpoint: oidcDiscoveryEndpoint,
		PublicKey:         opentdfCredentials.PublicKey,
	})
	if err != nil {
		log.Fatal(err)
	}

	opentdfCredentials.Tokens, err = oClient.Login()
	if err != nil {
		log.Fatal(err)
	}

	tomlCreds, err := toml.Marshal(opentdfCredentials)
	if err != nil {
		log.Fatal(err)
	}
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	fmt.Println("Writing credentials to: ", fmt.Sprintf("%s/.opentdf/credentials.toml", homedir))
	os.WriteFile(fmt.Sprintf("%s/.opentdf/credentials.toml", homedir), tomlCreds, 0644)
}
