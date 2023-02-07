package access

import (
	"crypto"
	"strings"
	"errors"
	// "net/url"
)

const schemaVersion = "1.1.0"
const VALUE_ = "/value/"
const ATTR_ = "/attr/"

type Attribute struct {
	URI           string          `json:"attribute"` // attribute
	PublicKey     crypto.PublicKey `json:"pubKey"`    // pubKey
	ProviderURI   string          `json:"kasUrl"`    // kasUrl
	SchemaVersion string           `json:"tdf_spec_version,omitempty"`
	Name          string           `json:"displayName"`// displayName
	//Default       bool             // isDefault
}


func getNamespaceFromUri(attr Attribute) (string, error) {
    // extract the namespace from an attribute uri
    var uri string = attr.URI
	if uri == "" {
		err := errors.New("Attribute has empty URI")
		return "", err
	}
	splits := strings.Split(uri, ATTR_)
	return splits[0], nil

}
