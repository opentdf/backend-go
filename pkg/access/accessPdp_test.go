package access

import (
	"testing"

	uuid "github.com/google/uuid"
	attrs "github.com/virtru/access-pdp/attributes"
)

// ######## Dissem tests ################

func TestWildcardDissemSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{},
			Dissem:         []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements:           []Entitlement{},
	}

	testDefinitions := []attrs.AttributeDefinition{}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestDissemSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements:           []Entitlement{},
	}

	testDefinitions := []attrs.AttributeDefinition{}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestDissemFailure(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{},
			Dissem: []string{"email1@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements:           []Entitlement{},
	}

	testDefinitions := []attrs.AttributeDefinition{}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

// ######## All Of tests ################

func TestAllOfSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestAllOfFailure(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
				Attribute{URI: "https://example.com/attr/Test1/value/B", Name: "Test1"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

// ######## Any Of tests ################

func TestAnyOfSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example3.com/attr/Test3/value/A", Name: "Test3"},
				Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example3.com",
			Name:      "Test3",
			Rule:      "anyOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestAnyOfFailure(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example3.com/attr/Test3/value/A", Name: "Test3"},
				Attribute{URI: "https://example3.com/attr/Test3/value/B", Name: "Test3"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example3.com",
			Name:      "Test3",
			Rule:      "anyOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

// ######## Hierarchy tests ################

func TestHierarchySuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example2.com/attr/Test2/value/C", Name: "Test2"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example2.com",
			Name:      "Test2",
			Rule:      "hierarchy",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestHierarchyFailure(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example2.com/attr/Test2/value/A", Name: "Test2"},
				Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
			},
			Dissem: []string{},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example2.com",
			Name:      "Test2",
			Rule:      "hierarchy",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

// ######## Dissem Attribute combination ############

func TestAttrDissemSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestAttrDissemFailure1(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

func TestAttrDissemFailure2(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
				Attribute{URI: "https://example.com/attr/Test1/value/B", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

func TestAttrDissemFailure3(t *testing.T) {
	var entityID string = ""

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
				Attribute{URI: "https://example.com/attr/Test1/value/B", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)
	if err != ErrPolicyDissemInvalid {
		t.Errorf("Output %v not equal to expected %v", output, ErrPolicyDissemInvalid)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}

func TestAttrDissemFailure4(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
					Attribute{URI: "https://example2.com/attr/Test2/value/B", Name: "Test2"},
					Attribute{URI: "https://example3.com/attr/Test3/value/C", Name: "Test3"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)

	if output != false {
		t.Errorf("Expected false, but got %v", err)
	}

	if err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}

func TestAttrDissemFailure5(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
		Body: Body{
			DataAttributes: []Attribute{
				Attribute{URI: "https://example.com/attr/Test1/value/A", Name: "Test1"},
			},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}

	testClaims := ClaimsObject{
		PublicKey:              "test-public-key",
		ClientPublicSigningKey: "test-client-public-signing-key",
		SchemaVersion:          "test-schema",
		Entitlements: []Entitlement{
			Entitlement{
				EntityID: "email2@example.com",
				EntityAttributes: []Attribute{
					Attribute{URI: "", Name: "Test1"},
				},
			},
		},
	}

	testDefinitions := []attrs.AttributeDefinition{
		attrs.AttributeDefinition{
			Authority: "https://example.com",
			Name:      "Test1",
			Rule:      "allOf",
			Order:     []string{"A", "B", "C"},
		},
	}

	output, err := canAccess(entityID, testPolicy, testClaims, testDefinitions)

	if output != false {
		t.Errorf("Expected false, but got %v", err)
	}

	if err == nil {
		t.Errorf("Expected error, but got %v", err)
	}
}
