package tdf3

import (
	"encoding/json"
	"testing"
)

func TestDeserializingAttributes(t *testing.T) {
	serializedAttr := `{ "attribute": "https://the.authority.example.com/suborg/attr/the%2Fattribute/val/a%20value" }`
	var attr Attribute
	err := json.Unmarshal([]byte(serializedAttr), &attr)
	if err != nil {
		t.Fatalf("Error unmarshaling: %v", err)
	}

	if attr.Authority != "https://the.authority.example.com/suborg" {
		t.Fatalf("Got [%s] for authority, wanted [%s]", attr.Authority, "https://the.authority.example.com/suborg")
	}
	if attr.Name != "the/attribute" {
		t.Fatalf("Got [%s] for attribute name, wanted [the/attribute]", attr.Name)
	}
	if attr.Value != "a value" {
		t.Fatalf("Got [%s] for attribute value, wanted [a value]", attr.Value)
	}
}

func TestSerializingAttributes(t *testing.T) {
	var toSerialize = Attribute{
		Name:      "1/2",
		Value:     "this is a value",
		Authority: "https://example.org/x",
	}

	serialized, err := json.Marshal(toSerialize)
	if err != nil {
		t.Fatalf("Error serializing")
	}

	unparsed := make(map[string]string)
	err = json.Unmarshal([]byte(serialized), &unparsed)
	if err != nil {
		t.Fatalf("error unmarshaling: %v", err)
	}

	if unparsed["attribute"] != "https://example.org/x/attr/1%2F2/value/this%20is%20a%20value" {
		t.Fatalf("didn't get the right attribute: %s", unparsed["attribute"])
	}
}

func TestDeserializingInvalidAttributes(t *testing.T) {
	var attr Attribute
	err := json.Unmarshal([]byte(`{"attribute": "https://example.org" }`), &attr)
	if err == nil {
		t.Fatalf("Should have failed")
	}
}
