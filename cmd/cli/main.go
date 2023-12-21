package main

import (
	"context"
	"log/slog"
)

func main() {
	ctx := context.Background()
	slog.InfoContext(ctx, "Starting...")
}
