package main

import (
	"context"
	"fmt"
	attributes "github.com/opentdf/backend-go/gen/attributes"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/opentdf/backend-go/gen/authorization"
	"google.golang.org/grpc"
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
	port := "50051"
	if os.Getenv("SERVER_PORT") != "" {
		port = os.Getenv("SERVER_PORT")
	}
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
	slog.InfoContext(ctx, fmt.Sprintf("Listening on %s...", port))
	s := grpc.NewServer()
	err = NewAuthorizationServer(s)
	if err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
	if err := s.Serve(l); err != nil {
		slog.ErrorContext(ctx, err.Error())
		panic(err)
	}
}

type Authorization struct {
	authorization.UnimplementedAuthorizationServiceServer
}

func NewAuthorizationServer(g *grpc.Server) error {
	as := &Authorization{}
	authorization.RegisterAuthorizationServiceServer(g, as)
	return nil
}

func (a *Authorization) IsAuthorized(ctx context.Context, r *authorization.DecisionRequest) (*authorization.DecisionResponse, error) {
	slog.InfoContext(ctx, r.String())
	return &authorization.DecisionResponse{
		EntityChainId:        "abc123",
		ResourceAttributesId: "def456",
		Action:               nil,
		Decision:             authorization.DecisionResponse_DECISION_PERMIT,
		Obligations:          nil,
	}, nil
}
func (a *Authorization) GetEntitlements(context.Context, *authorization.GetEntitlementsRequest) (*authorization.GetEntitlementsResponse, error) {
	response := authorization.GetEntitlementsResponse{
		Entitlements: make([]*authorization.EntityEntitlements, 1),
	}
	response.Entitlements[0] = &authorization.EntityEntitlements{
		EntityId:                 "e1",
		AttributeValueReferences: make([]*attributes.AttributeValueReference, 1),
	}
	response.Entitlements[0].AttributeValueReferences[0].Ref = &attributes.AttributeValueReference_AttributeFqn{
		AttributeFqn: "https://opentdf.io/attr/a1/value/v1",
	}
	return &response, nil
}

type ctxHandler struct {
	slog.Handler
}

func (h *ctxHandler) Handle(ctx context.Context, record slog.Record) error {
	m, ok := grpc.Method(ctx)
	if ok {
		record.AddAttrs(slog.String("service-method", m))
	}
	ua, ok := ctx.Value("user-agent").(string)
	if ok {
		record.AddAttrs(slog.String("user-agent", ua))
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
