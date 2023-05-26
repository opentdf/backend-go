package access

import (
	"github.com/google/uuid"
	attrs "github.com/virtru/access-pdp/attributes"
)

type Policy struct {
	UUID uuid.UUID
	Body Body
}

type Body struct {
	DataAttributes []Attribute
	Dissem         []string
}

func getNamespacesFromAttributes(body Body) ([]string, error) {
	// extract the namespace from an attribute uri
	var dataAttributes []Attribute = body.DataAttributes
	namespaces := make(map[string]bool)
	for _, attr := range dataAttributes {
		instance, err := attrs.ParseInstanceFromURI(attr.URI)
		if err != nil {
			// logger.Warn("Error getting attribute namespace")
			return nil, err
		}
		namespaces[instance.Authority] = true
	}

	// get unique
	keys := make([]string, len(namespaces))
	indx := 0
	for key, _ := range namespaces {
		keys[indx] = key
		indx++
	}

	return keys, nil
}
