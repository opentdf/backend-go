package access

import (
	"encoding/json"
	"fmt"
	attrs "github.com/virtru/access-pdp/attributes"
	"log"
	"net/http"
)

// const attribute_host = "http://attributes:4020"
const attribute_host = "http://localhost:65432/api/attributes"

func fetchAttributes(namespaces []string) ([]attrs.AttributeDefinition, error) {
	var definitions []attrs.AttributeDefinition
	for _, ns := range namespaces {
		attrDefs, err := fetchAttributesForNamespace(ns)
		if err != nil {
			// logger.Warn("Error creating http request to attributes sercice")
			log.Printf("Error fetching attributes for namespace %s", ns)
			return nil, err
		}
		definitions = append(definitions, attrDefs...)
	}
	return definitions, nil
}

func fetchAttributesForNamespace(namespace string) ([]attrs.AttributeDefinition, error) {
	log.Println("Fetching for ", namespace)
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, attribute_host+"/v1/attrName", nil)
	if err != nil {
		// logger.Warn("Error creating http request to attributes sercice")
		log.Println("Error creating http request to attributes sercice")
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("authority", namespace)
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		// logger.Warn("Error executing http request to attributes service")
		log.Println("Error executing http request to attributes service")
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		err := fmt.Errorf("Issue getting definitions from attributes sevices. Recieved error %v %v", resp.StatusCode, http.StatusText(resp.StatusCode))
		return nil, err
	}

	var definitions []attrs.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		// logger.Warn("Error parsing response from attributes service")
		log.Println("Error parsing response from attributes service")
		return nil, err
	}

	return definitions, nil
}
