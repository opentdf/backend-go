package access


import (
	"net/http"
	"net/url"
	"log"
	// "io/ioutil"
	// "strings"
	"encoding/json"
	attrs "github.com/virtru/access-pdp/attributes"
)
// const attribute_host = "http://attributes:4020"
const attribute_host = "http://localhost:65432/api/attributes"


func fetchAttributes(namespaces []string) []attrs.AttributeDefinition {
	var definitions []attrs.AttributeDefinition
	for _, ns := range namespaces {
		attrDefs := fetchAttributesForNamespace(ns)
		definitions = append(definitions, attrDefs...)
	}
	return definitions
}

func fetchAttributesForNamespace(namespace string) []attrs.AttributeDefinition {
	log.Println("Fetching for %v", namespace)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, attribute_host+"/v1/attrName", nil)
	if err != nil {
		log.Fatal(err)
	}

  	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("authority", namespace)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		log.Panic("Errored when sending request to the server")
	}

	defer resp.Body.Close()
	var definitions []attrs.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		// FIXME handle error
		log.Panic(err)
	}

	// log.Println(resp.Status)
	// add steps for checking status
	// log.Printf("%+v", definitions)
	return definitions
}