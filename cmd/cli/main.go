package main

import (
	"context"
	"log/slog"
	"os"
	"os/user"
	"strings"

	"github.com/opentdf/backend-go/gen/authorization"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	ctx := context.Background()
	logLevel := slog.LevelInfo
	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	case "DEBUG":
		logLevel = slog.LevelDebug
	}
	if os.Getenv("LOG_FORMAT") == "json" {
		h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
		slog.SetDefault(slog.New(&ctxHandler{
			Handler: h,
		}))
	} else {
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
		slog.SetDefault(slog.New(&ctxHandler{
			Handler: h,
		}))
	}
	slog.InfoContext(ctx, "Starting...")
	pid := os.Getpid()
	currentUser, err := user.Current()
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
	}
	ctx = context.WithValue(ctx, "username", currentUser.Username)
	ctx = context.WithValue(ctx, "pid", pid)
	slog.InfoContext(ctx, "Ascertaining...")
	do := grpc.WithTransportCredentials(insecure.NewCredentials())
	host := "localhost:50051"
	if os.Getenv("AUTHORIZATION_HOST") != "" {
		host = os.Getenv("AUTHORIZATION_HOST")
	}
	cc, err := grpc.Dial(host, do)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
	ac := authorization.NewAuthorizationServiceClient(cc)
	in := authorization.DecisionRequest{}
	out, err := ac.IsAuthorized(ctx, &in)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
	slog.InfoContext(ctx, out.String())
	slog.InfoContext(ctx, "Listing...")
	files, err := os.ReadDir(".")
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
	for _, file := range files {
		slog.InfoContext(ctx, "ls", "name", file.Name(), "type", file.Type())
	}
	slog.InfoContext(ctx, "Stopping...")
	os.Exit(0)
}

type ctxHandler struct {
	slog.Handler
}

func (h *ctxHandler) Handle(ctx context.Context, record slog.Record) error {
	username, ok := ctx.Value("username").(string)
	if ok {
		record.AddAttrs(slog.String("username", username))
	}
	pid, ok := ctx.Value("pid").(int)
	if ok {
		record.AddAttrs(slog.Int("pid", pid))
	}
	return h.Handler.Handle(ctx, record)
}

func (h *ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ctxHandler{
		Handler: h.Handler.WithAttrs(attrs),
	}
}

func (h *ctxHandler) WithGroup(name string) slog.Handler {
	return &ctxHandler{
		Handler: h.Handler.WithGroup(name),
	}
}
