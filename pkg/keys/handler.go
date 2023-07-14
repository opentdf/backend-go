package keys

import (
	"encoding/json"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Provider struct {
	jwk.Set
}

func (p *Provider) Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(p.Set)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
