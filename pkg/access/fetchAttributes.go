package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"log"
	"net/http"

	"github.com/virtru/access-pdp/attributes"
)

const (
	ErrAttributeDefinitionsUnmarshal   = Error("attribute definitions unmarshal")
	ErrAttributeDefinitionsServiceCall = Error("attribute definitions service call unexpected")
)

attributeHost, attrHostDefined := os.LookupEnv("ATTR_AUTHORITY_HOST")
if !attrHostDefined {
	attributeHost = "http://attributes:4020"
}

func fetchAttributes(ctx context.Context, namespaces []string) ([]attributes.AttributeDefinition, error) {
	var definitions []attributes.AttributeDefinition
	for _, ns := range namespaces {
		attrDefs, err := fetchAttributesForNamespace(ctx, ns)
		if err != nil {
			// logger.Warn("Error creating http request to attributes service")
			log.Printf("Error fetching attributes for namespace %s", ns)
			return nil, err
		}
		definitions = append(definitions, attrDefs...)
	}
	return definitions, nil
}

func fetchAttributesForNamespace(ctx context.Context, namespace string) ([]attributes.AttributeDefinition, error) {
	log.Println("Fetching for ", namespace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, attributeHost+"/v1/attrName", nil)
	if err != nil {
		log.Println("Error creating http request to attributes service")
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("authority", namespace)
	req.URL.RawQuery = q.Encode()
	var httpClient http.Client
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Println("Error executing http request to attributes service")
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("status code %v %v", resp.StatusCode, http.StatusText(resp.StatusCode))
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	var definitions []attributes.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		log.Println("Error parsing response from attributes service")
		return nil, errors.Join(ErrAttributeDefinitionsUnmarshal, err)
	}

	return definitions, nil
}
