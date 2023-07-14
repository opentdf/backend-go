package wellknown

import (
	"encoding/json"
	"net/http"
)

type OpenTdfConfiguration struct {
	JwksUri string `json:"jwks_uri"`
	Issuer  string `json:"issuer,omitempty"`
	//AuthorizationEndpoint                  string   `json:"authorization_endpoint,omitempty"`
	//TokenEndpoint                          string   `json:"token_endpoint,omitempty"`
	//UserinfoEndpoint                       string   `json:"userinfo_endpoint,omitempty"`
	//RevocationEndpoint                     string   `json:"revocation_endpoint,omitempty"`
	//ResponseTypesSupported                 []string `json:"response_types_supported,omitempty"`
	//SubjectTypesSupported                  []string `json:"subject_types_supported,omitempty"`
	//IdTokenSigningAlgValuesSupported       []string `json:"id_token_signing_alg_values_supported,omitempty"`
	//UserinfoSigningAlgValuesSupported      []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	//RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`
	//ResponseModesSupported                 []string `json:"response_modes_supported,omitempty"`
	//GrantTypesSupported                    []string `json:"grant_types_supported,omitempty"`
	//ClaimsSupported                        []string `json:"claims_supported,omitempty"`
	//ScopesSupported                        []string `json:"scopes_supported,omitempty"`
	//CodeChallengeMethodsSupported          []string `json:"code_challenge_methods_supported,omitempty"`
	//RegistrationEndpoint                   string   `json:"registration_endpoint,omitempty"`
	//TokenEndpointAuthMethodsSupported      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	//ClaimsParameterSupported               bool     `json:"claims_parameter_supported,omitempty"`
	//RequestParameterSupported              bool     `json:"request_parameter_supported,omitempty"`
	//RequestUriParameterSupported           bool     `json:"request_uri_parameter_supported,omitempty"`
	//RequireRequestUriRegistration          bool     `json:"require_request_uri_registration,omitempty"`
}

type Provider struct {
	OpenTdfConfiguration
}

func (p *Provider) Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(p.OpenTdfConfiguration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
