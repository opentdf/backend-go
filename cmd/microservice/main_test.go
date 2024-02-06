package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestLoadAuditHookAuditEnabled(t *testing.T) {
	os.Setenv("AUDIT_ENABLED", "true")
	auditHook := loadAuditHook()

	if auditHook == nil {
		t.Error("Should return function")
	}
}

func TestLoadAuditHookAuditDisabled(t *testing.T) {
	os.Setenv("AUDIT_ENABLED", "false")
	auditHook := loadAuditHook()

	if auditHook == nil {
		t.Error("Should return function")
	}
}

func TestLoadIdentityProvider(t *testing.T) {
	// Set up mock server for OIDC discovery
	discoveryHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer": "http://localhost:65432/auth/realms/tdf"}`))
	})
	discoveryServer := httptest.NewServer(discoveryHandler)
	defer discoveryServer.Close()

	// Set up mock server for OIDC configuration
	configHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer": "http://localhost:65432/auth/realms/tdf"}`))
	})
	configServer := httptest.NewServer(configHandler)
	defer configServer.Close()
	// Set environment variables for testing
	os.Setenv("OIDC_ISSUER_URL", discoveryServer.URL)
	os.Setenv("OIDC_DISCOVERY_BASE_URL", configServer.URL)

	fmt.Println("1.", discoveryServer.URL)
	fmt.Println("2.", configServer.URL)
	// Call the function being tested
	oidcVerifier := loadIdentityProvider()

	fmt.Printf("%+v \n", oidcVerifier)

	ctx := context.Background()
	idToken, err := oidcVerifier.Verify(ctx, "Bearer ..")

	fmt.Println("idToken", idToken)
	fmt.Println("err", err)

	// TODO Check if the returned provider is not nil
	if "provider" == "nil" {
		t.Errorf("Expected non-nil provider, got nil")
	}
}
