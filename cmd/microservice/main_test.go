package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/opentdf/backend-go/pkg/access"
)

func TestInferLoggerDefaults(t *testing.T) {
	h := inferLogger("", "")
	_, ok := h.Handler().(*slog.TextHandler)
	if !ok {
		t.Error("should default to TextHandler")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("should default to INFO")
	}
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("should not support DEBUG by default")
	}
}

func TestInferLoggerType(t *testing.T) {
	h := inferLogger("", "json")
	_, ok := h.Handler().(*slog.JSONHandler)
	if !ok {
		t.Error("wrong handler type")
	}

	h = inferLogger("", "jSoN")
	_, ok = h.Handler().(*slog.JSONHandler)
	if !ok {
		t.Error("wrong handler type")
	}

	h = inferLogger("", "idkwhatever")
	_, ok = h.Handler().(*slog.TextHandler)
	if !ok {
		t.Error("wrong handler type")
	}
}

func TestInferLogLevel(t *testing.T) {
	h := inferLogger("info", "")
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("should be at INFO")
	}
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("should not be at DEBUG")
	}

	h = inferLogger("DEbUG", "")
	if !h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("should be at DEBUG")
	}

	h = inferLogger("warn", "")
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("should be at warn")
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("should not be at info")
	}

	h = inferLogger("warnING", "")
	if !h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("should be at warn")
	}
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("should not be at info")
	}

	h = inferLogger("erroR", "")
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("should be at error")
	}
	if h.Enabled(context.Background(), slog.LevelWarn) {
		t.Error("should not be at warn")
	}
}

func TestValidatePort(t *testing.T) {
	p, err := validatePort("")
	if p != 0 || err != nil {
		t.Error("empty SERVER_PORT should default properly")
	}
	p, err = validatePort("invalid")
	if p != 0 || !errors.Is(err, access.ErrConfig) {
		t.Error("invalid error code")
	}
	p, err = validatePort("-1000")
	if p != 0 || !errors.Is(err, access.ErrConfig) {
		t.Error("invalid error code")
	}
	p, err = validatePort("65536")
	if p != 0 || !errors.Is(err, access.ErrConfig) {
		t.Error("invalid error code")
	}
}

//func TestLoadAuditHookAuditEnabled(t *testing.T) {
//	os.Setenv("AUDIT_ENABLED", "true")
//	auditHook := loadAuditHook()
//
//	if auditHook == nil {
//		t.Error("Should return function")
//	}
//	os.Setenv("AUDIT_ENABLED", "false")
//}
//
//func TestLoadAuditHookAuditDisabled(t *testing.T) {
//	os.Setenv("AUDIT_ENABLED", "false")
//	auditHook := loadAuditHook()
//
//	if auditHook == nil {
//		t.Error("Should return function")
//	}
//	os.Unsetenv("AUDIT_ENABLED")
//}
//
//func TestLoadIdentityProvider(t *testing.T) {
//	// Set up mock server for OIDC discovery
//	discoveryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Header().Set("Content-Type", "application/json")
//		w.Write([]byte(`{"issuer": "http://localhost:65432/auth/realms/tdf"}`))
//	})
//	discoveryServer := httptest.NewServer(discoveryHandler)
//	defer discoveryServer.Close()
//
//	// Set up mock server for OIDC configuration
//	configHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		w.Header().Set("Content-Type", "application/json")
//		w.Write([]byte(`{"issuer": "http://localhost:65432/auth/realms/tdf"}`))
//	})
//	configServer := httptest.NewServer(configHandler)
//	defer configServer.Close()
//
//	os.Setenv("OIDC_ISSUER_URL", discoveryServer.URL)
//	os.Setenv("OIDC_DISCOVERY_BASE_URL", configServer.URL)
//
//	oidcVerifier := loadIdentityProvider()
//
//	if reflect.TypeOf(oidcVerifier).String() != "oidc.IDTokenVerifier" {
//		t.Errorf("Expected non-nil provider, got nil")
//	}
//
//	os.Unsetenv("OIDC_ISSUER_URL")
//	os.Unsetenv("OIDC_DISCOVERY_BASE_URL")
//}
//
//func TestNewHSMContext(t *testing.T) {
//	pin := "12345"
//	os.Setenv("PKCS11_PIN", pin)
//	os.Setenv("PKCS11_MODULE_PATH", "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so")
//
//	hc, err := newHSMContext()
//	defer destroyHSMContext(hc)
//
//	if err != nil {
//		t.Errorf("Expected no error")
//	}
//
//	if reflect.TypeOf(hc).String() != "*main.hsmContext" {
//		t.Errorf("Expected non-nil hsmContext, got nil")
//	}
//
//	if hc.pin != pin {
//		t.Errorf("Expected correct pin")
//	}
//	os.Unsetenv("PKCS11_PIN")
//	os.Unsetenv("PKCS11_MODULE_PATH")
//}
//
//func TestNewHSMSession(t *testing.T) {
//	os.Setenv("PKCS11_SLOT_INDEX", "0")
//	os.Setenv("PKCS11_PIN", "12345")
//	os.Setenv("PKCS11_MODULE_PATH", "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so")
//
//	hc, _ := newHSMContext()
//	defer destroyHSMContext(hc)
//
//	hcSession, err := newHSMSession(hc)
//	defer destroyHSMSession(hcSession)
//
//	if err != nil {
//		t.Errorf("Expected no error")
//	}
//
//	if reflect.TypeOf(hcSession).String() != "*main.hsmSession" {
//		t.Errorf("Expected non-nil main.hsmSession, got nil")
//	}
//
//	os.Unsetenv("PKCS11_SLOT_INDEX")
//	os.Unsetenv("PKCS11_PIN")
//	os.Unsetenv("PKCS11_MODULE_PATH")
//}
//
//func TestNewHSMSessionFailure(t *testing.T) {
//	os.Setenv("PKCS11_SLOT_INDEX", "INVALID SLOT")
//	os.Setenv("PKCS11_PIN", "12345")
//	os.Setenv("PKCS11_MODULE_PATH", "/usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so")
//
//	hc, _ := newHSMContext()
//	_, err := newHSMSession(hc)
//
//	if err == nil {
//		t.Errorf("Expected an error")
//	}
//
//	if strings.Contains(access.ErrHSM.Error(), err.Error()) {
//		t.Errorf("Expected hsm error")
//	}
//
//	//defer destroyHSMContext(hc)
//	//defer destroyHSMSession(hs)
//
//	os.Unsetenv("PKCS11_SLOT_INDEX")
//	os.Unsetenv("PKCS11_PIN")
//	os.Unsetenv("PKCS11_MODULE_PATH")
//}
