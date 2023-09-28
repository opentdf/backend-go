package tdf3

type KeyAccess struct {
	EncryptedMetadata []byte `json:"encryptedMetadata,omitempty"`
	PolicyBinding     []byte `json:"policyBinding"`
	Protocol          string `json:"protocol"`
	Type              string `json:"type"`
	URL               string `json:"url"`
	WrappedKey        []byte `json:"wrappedKey,omitempty"`
	Header            []byte `json:"header,omitempty"`
	Algorithm         string `json:"algorithm,omitempty"`
}

type Metadata struct {
	Algorithm  string `json:"algorithm"`
	IV         []byte `json:"iv"`
	CipherText []byte `json:"ciphertext"`
}
