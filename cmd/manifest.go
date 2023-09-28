/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	tdf3 "github.com/opentdf/backend-go/pkg/tdf3/client"
	"github.com/spf13/cobra"
)

// manifestCmd represents the manifest command
var manifestCmd = &cobra.Command{
	Use:   "manifest",
	Short: "Get TDF manifest",
	Run:   manifest,
}

func init() {
	rootCmd.AddCommand(manifestCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// policyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// policyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	manifestCmd.Flags().String("file", "", "TDF file to extract policy from")
}

func manifest(cmd *cobra.Command, _ []string) {
	file, err := cmd.Flags().GetString("file")
	if err != nil {
		log.Fatal(err)
	}

	client, err := tdf3.NewTDFClient()
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
	manifest, err := client.GetManifest(tdf, size.Size())
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)
	fmt.Printf("TDF Manifest in %s\n", duration)

	jsonTDF, err := json.MarshalIndent(&manifest, "", "	")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(jsonTDF))
}
