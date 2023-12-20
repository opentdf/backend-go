package main

import (
	"context"
	"log/slog"
	"testing"
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
