package access

import (
	"github.com/google/uuid"
)

type Policy struct {
	UUID uuid.UUID
	Body Body
}

type Body struct {
	DataAttributes []Attribute
	Dissem         []string
}

func getNamespacesFromAttributes(body Body) []string {
    // extract the namespace from an attribute uri
    var dataAttributes []Attribute = body.DataAttributes
	namespaces := make(map[string]bool)
	for _, attr := range dataAttributes {
		ns := getNamespaceFromUri(attr)
		namespaces[ns] = true
	}

	keys := make([]string, len(namespaces))
	indx := 0
	for key, _ := range namespaces {
	keys[indx] = key
	indx++
	}

	return keys
}