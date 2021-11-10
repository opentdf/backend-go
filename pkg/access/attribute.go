package access

import (
	"crypto"
	"net/url"
)

const schemaVersion = "1.1.0"

type Attribute struct {
	URI           url.URL          `json:"attribute"` // attribute
	PublicKey     crypto.PublicKey `json:"pubKey"`    // pubKey
	ProviderURI   url.URL          `json:"kasUrl"`    // kasUrl
	SchemaVersion string           `json:"schemaVersion"`
	//Default       bool             // isDefault
	//Name          string           // displayName
}
