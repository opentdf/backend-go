package access

// const schemaVersion = "1.1.0"

type ClaimsObject struct{
	PublicKey				string		`json:"public_key"`
	ClientPublicSigningKey	string 		`json:"client_public_signing_key"`
	SchemaVersion 			string 		`json:"tdf_spec_version,omitempty"`
	SubjectAttributes 		[]Attribute	`json:"subject_attributes"`
}