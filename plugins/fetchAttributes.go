package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"

	attrs "github.com/virtru/access-pdp/attributes"
)

type attributePlug struct{}

var (
	ErrAttributeDefinitionsUnmarshal   = errors.New("attribute definitions unmarshal")
	ErrAttributeDefinitionsServiceCall = errors.New("attribute definitions service call unexpected")
)

// const attributeHost = "http://attributes:4020"
const attributeHost = "http://localhost:65432/api/attributes"

func fetchAttributesForNamespace(ctx context.Context, namespace string) ([]attrs.AttributeDefinition, error) {
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

	var definitions []attrs.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		log.Println("Error parsing response from attributes service")
		return nil, errors.Join(ErrAttributeDefinitionsUnmarshal, err)
	}

	return definitions, nil
}

func (attributePlug) FetchAllAttributes(ctx context.Context, namespaces []string) ([]attrs.AttributeDefinition, error) {
    var definitions []attrs.AttributeDefinition
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


func GetPluginIface() (f interface{}, err error) {
    f = attributePlug{}
    return f, nil
}
