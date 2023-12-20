package access

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/opentdf/backend-go/internal/version"
)

func (p *Provider) Version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	j, err := json.Marshal(version.GetVersion())
	if err != nil {
		http.Error(w, "serialization error", http.StatusInternalServerError)
		slog.ErrorContext(r.Context(), "json version Marshal", "err", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(j)
}
