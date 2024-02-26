package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
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

func TestNewHSMContext(t *testing.T) {
	pin := "12345"
	os.Setenv("PKCS11_SLOT_INDEX", "0")
	os.Setenv("PKCS11_PIN", pin)
	// TODO
	//PATH := getHSMPath()
	// // var CI_LINUX_HSM_PATH = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
	os.Setenv("PKCS11_MODULE_PATH", "/usr/lib/softhsm/libsofthsm2.so")
	hc, err := newHSMContext()
	defer destroyHSMContext(hc)

	if err != nil {
		t.Errorf("Expected no error")
	}

	if reflect.TypeOf(hc).String() != "*main.hsmContext" {
		t.Errorf("Expected non-nil hsmContext, got nil")
	}

	if hc.pin != pin {
		t.Errorf("Expected correct pin")
	}
	os.Unsetenv("PKCS11_PIN")
	os.Unsetenv("PKCS11_SLOT_INDEX")
	os.Unsetenv("PKCS11_MODULE_PATH")
}
