package access

import (
	"context"
	"github.com/jarcoal/httpmock"
	"github.com/virtru/access-pdp/attributes"
	"net/http"
	"testing"
)

func TestFetchAttributes(t *testing.T) {
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
			//GroupBy: &AttributeInstance{
			//	// Populate the fields of AttributeInstance as needed
			//},
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
			resp, err := httpmock.NewJsonResponse(200, mockDefinitions)
			return resp, err
		},
	)

	output, err := fetchAttributes(ctx, namespaces)

	if err != nil {
		t.Error(err)
	}

	if len(output) == 0 {
		t.Errorf("Output %v not equal to expected %v", output, mockDefinitions)
	}
}
