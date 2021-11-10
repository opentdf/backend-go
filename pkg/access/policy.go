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
