package access

import (
	"context"
	"net/http"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/virtru/access-pdp/attributes"
)

type WrongAttributeDefinition struct {
	Wrong    string `json:"wrong"`
	Type     string `json:"type"`
	Of       string `json:"of"`
	Response string `json:"response"`
}

func TestFetchAttributesSuccess(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	ctx := context.Background()
	namespaces := []string{"namespace1", "namespace2"}

	mockDefinitions := []attributes.AttributeDefinition{
		{
			Authority: "namespace1",
			Name:      "attribute1",
			Rule:      "rule1",
			State:     "active",
			Order:     []string{"value1", "value2", "value3"},
		},
		{
			Authority: "namespace2",
			Name:      "attribute2",
			Rule:      "rule2",
			Order:     []string{"valueA", "valueB", "valueC"},
		},
	}

	httpmock.RegisterResponder("GET", "http://localhost:65432/api/attributes/v1/attrName",
		func(req *http.Request) (*http.Response, error) {
			authority := req.URL.Query().Get("authority")

			if authority == "namespace1" {
				resp, err := httpmock.NewJsonResponse(200, mockDefinitions[:1])
				return resp, err
			}

			// namespace2
			resp, err := httpmock.NewJsonResponse(200, mockDefinitions[1:])
			return resp, err
		},
	)

	output, err := fetchAttributes(ctx, namespaces)

	if err != nil {
		t.Error(err)
	}

	if len(output) != len(mockDefinitions) {
		t.Errorf("Output %v not equal to expected %v", output, mockDefinitions)
	}
}

func TestFetchAttributesFailure(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	ctx := context.Background()
	namespaces := []string{"namespace1", "namespace2"}

	mockWrongResponse := WrongAttributeDefinition{
		Wrong:    "mock",
		Type:     "mock",
		Of:       "mock",
		Response: "mock",
	}

	httpmock.RegisterResponder("GET", "http://localhost:65432/api/attributes/v1/attrName",
		func(req *http.Request) (*http.Response, error) {
			resp, err := httpmock.NewJsonResponse(200, mockWrongResponse)
			return resp, err
		},
	)

	output, err := fetchAttributes(ctx, namespaces)

	t.Log(err)
	t.Log(output)

	if len(output) != 0 {
		t.Errorf("Output %v not equal to expected %v", len(output), 0)
	}

	if err == nil {
		t.Errorf("Error expected, but got %v", err)
	}
}

func TestFetchAttributesFailure1(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	ctx := context.Background()
	namespaces := []string{"namespace1", "namespace2"}

	httpmock.RegisterResponder("GET", "http://localhost:65432/api/attributes/v1/attrName",
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(500, ""), nil
		},
	)

	output, err := fetchAttributes(ctx, namespaces)

	if err == nil {
		t.Error("Should throw an error")
	}

	if len(output) != 0 {
		t.Errorf("Output %v not equal to expected %v", len(output), 0)
	}
}

func TestFetchAttributesFailure2(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	ctx := context.Background()
	namespaces := []string{"namespace1", "namespace2"}

	httpmock.RegisterResponder("GET", "http://localhost:65432/api/attributes/v1/attrName",
		func(req *http.Request) (*http.Response, error) {
			return nil, Error("Mock http client error")
		},
	)

	output, err := fetchAttributes(ctx, namespaces)

	if err == nil {
		t.Error("Should throw an error")
	}

	if len(output) != 0 {
		t.Errorf("Output %v not equal to expected %v", len(output), 0)
	}
}

func TestFetchAttributesForNamespaceFailure(t *testing.T) {
	namespaces := []string{"namespace1", "namespace2"}

	output, err := fetchAttributes(nil, namespaces)

	if err == nil {
		t.Error("Should throw an error")
	}

	if len(output) != 0 {
		t.Errorf("Output %v not equal to expected %v", len(output), 0)
	}
}
