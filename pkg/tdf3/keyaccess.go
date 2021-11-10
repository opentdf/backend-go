package tdf3

//type KeyAccess struct {
//	Type          KeyStorage
//	Server        url.URL
//	Protocol      string
//	Key           []byte // wrappedKey
//	PolicyBinding PolicyBinding
//	Metadata      interface{}
//	SchemaVersion string
//}
//
//type KeyStorage int
//
//const (
//	Remote KeyStorage = iota
//	Wrapped
//	RemoteWrapped
//)
//
//type PolicyBinding struct {
//	Algorithm string
//	Hash      string
//}

type KeyAccess struct {
	EncryptedMetadata string `json:"encryptedMetadata,omitempty"`
	PolicyBinding     string `json:"policyBinding,omitempty"`
	Protocol          string `json:"protocol"`
	Type              string `json:"type"`
	URL               string `json:"url"`
	WrappedKey        []byte `json:"wrappedKey,omitempty"`
	Header            []byte `json:"header,omitempty"`
}
