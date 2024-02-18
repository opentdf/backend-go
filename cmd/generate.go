/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/arkavo/backend-go/pkg/tdf3"
	tdfClient "github.com/arkavo/backend-go/pkg/tdf3/client"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// generateCmd represents the generate command
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Create a TDF",
	Run:   generateTDF,
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().String("file", "", "File to wrap with TDF")
	generateCmd.Flags().String("text", "", "Text to wrap with TDF")
	generateCmd.Flags().String("output", "file://test.tdf", "Output file")
	generateCmd.Flags().Int("keysize", 256, "Key size")
	generateCmd.Flags().StringArray("attribute", []string{}, "Attribute to apply to the TDF")
	generateCmd.Flags().String("keySplitType", "split", "Key split type can be split or shamir")
	generateCmd.Flags().String("encryptedMetatData", "", "Encrypted metadata")
}

func generateTDF(cmd *cobra.Command, _ []string) {
	var (
		opentdfCredentials OpenTDFCredentials
		reader             io.Reader
		output             string
	)

	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Can't read config:", err)
		os.Exit(1)
	}

	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	text, err := cmd.Flags().GetString("text")
	if err != nil {
		log.Fatal(err)
	}

	o, err := cmd.Flags().GetString("output")
	if err != nil {
		log.Fatal(err)
	}

	attributes, err := cmd.Flags().GetStringArray("attribute")
	if err != nil {
		log.Fatal(err)
	}

	keySplitType, err := cmd.Flags().GetString("keySplitType")
	if err != nil {
		log.Fatal(err)
	}

	encryptedMetatData, err := cmd.Flags().GetString("encryptedMetatData")
	if err != nil {
		log.Fatal(err)
	}

	if !strings.HasPrefix(o, "file://") && !strings.HasPrefix(o, "https://") {
		log.Fatal("Output must be either file:// or https://")
	}

	if strings.HasPrefix(o, "file://") {
		output = strings.TrimPrefix(o, "file://")
	}

	if strings.HasPrefix(o, "https://") {
		output = strings.TrimPrefix(o, "https://")
	}

	if file == "" && text == "" {
		log.Fatal("Must specify either --file or --text")
	}

	if file != "" && text != "" {
		log.Fatal("Must specify either --file or --text, not both")
	}

	if file != "" {
		reader, err = os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer reader.(*os.File).Close()
	}

	if text != "" {
		reader = bytes.NewBufferString(text)
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

	kasEndpoint := viper.GetStringSlice(fmt.Sprintf("profiles.%s.kasendpoint", opentdfCredentials.Profile))

	client, err := tdfClient.NewTDFClient(tdfClient.TDFClientOptions{
		KasEndpoint: kasEndpoint,
	})
	if err != nil {
		log.Fatal(err)
	}

	var parsedAttributes = []tdf3.Attribute{}
	for _, attr := range attributes {
		var parsedAttr tdf3.Attribute
		if err := parsedAttr.ParseAttributeFromString(attr); err != nil {
			log.Fatal(err)
		}
		parsedAttributes = append(parsedAttributes, parsedAttr)
	}

	outFile, err := os.Create(output)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	start := time.Now()
	if err = client.Create(reader, outFile, &tdfClient.TDFCreateOptions{
		Attributes:         parsedAttributes,
		EncryptedMetadata:  []byte(encryptedMetatData),
		KeySplitType:       keySplitType,
		IsPayloadEncrypted: true,
	}); err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("TDF generated in %s\n", duration)
	fmt.Println("TDF generated")
}
