package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/virtru/access-pdp/attributes"
)

const (
	ErrAttributeDefinitionsUnmarshal   = Error("attribute definitions unmarshal")
	ErrAttributeDefinitionsServiceCall = Error("attribute definitions service call unexpected")
)

// const attributeHost = "http://attributes:4020"
const attributeHost = "http://localhost:65432/api/attributes"

func fetchAttributes(ctx context.Context, log slog.Logger, namespaces []string) ([]attributes.AttributeDefinition, error) {
	var definitions []attributes.AttributeDefinition
	for _, ns := range namespaces {
		attrDefs, err := fetchAttributesForNamespace(ctx, log, ns)
		if err != nil {
			log.Error("unable to fetch attributes for namespace", "err", err, "namespace", ns)
			return nil, err
		}
		definitions = append(definitions, attrDefs...)
	}
	return definitions, nil
}

func fetchAttributesForNamespace(ctx context.Context, log slog.Logger, namespace string) ([]attributes.AttributeDefinition, error) {
	log.Debug("Fetching", "namespace", namespace)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, attributeHost+"/v1/attrName", nil)
	if err != nil {
		log.Error("unable to create http request to attributes service", "namespace", namespace, "attributeHost", attributeHost)
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Add("authority", namespace)
	req.URL.RawQuery = q.Encode()
	var httpClient http.Client
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Error("failed http request to attributes service", "err", err, "namespace", namespace, "attributeHost", attributeHost, "req", req)
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Error("failed to close http request to attributes service", "err", err, "namespace", namespace, "attributeHost", attributeHost, "req", req)
		}
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("status code %v %v", resp.StatusCode, http.StatusText(resp.StatusCode))
		return nil, errors.Join(ErrAttributeDefinitionsServiceCall, err)
	}

	var definitions []attributes.AttributeDefinition
	err = json.NewDecoder(resp.Body).Decode(&definitions)
	if err != nil {
		log.Error("failed to parse response from attributes service", "err", err, "namespace", namespace, "attributeHost", attributeHost, "req", req)
		return nil, errors.Join(ErrAttributeDefinitionsUnmarshal, err)
	}

	return definitions, nil
}
