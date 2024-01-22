package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/opentdf/backend-go/gen/attributes"
	"github.com/opentdf/backend-go/gen/authorization"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// XRequestIDKey is metadata key name for request ID
var XRequestIDKey = "x-request-id"

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

func (a *Authorization) GetDecisions(ctx context.Context, r *authorization.GetDecisionsRequest) (*authorization.GetDecisionsResponse, error) {
	slog.InfoContext(ctx, r.String())
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		slog.InfoContext(ctx, strings.Join(metadata.ValueFromIncomingContext(ctx, "X-Request-Id"), "|"))
		v := md.Get("X-Request-Id")
		slog.InfoContext(ctx, "X-Request-Id", fmt.Sprintf("%v", v))
	}
	v := metadata.ValueFromIncomingContext(ctx, "X-Request-Id")
	slog.InfoContext(ctx, fmt.Sprintf("ValueFromIncomingContext %v", v))
	slog.InfoContext(ctx, r.String())
	dr := &authorization.GetDecisionsResponse{
		DecisionResponses: make([]*authorization.DecisionResponse, 1),
	}
	dr.DecisionResponses[0] = &authorization.DecisionResponse{
		EntityChainId:        "abc123",
		ResourceAttributesId: "def456",
		Action:               nil,
		Decision:             authorization.DecisionResponse_DECISION_PERMIT,
		Obligations:          nil,
	}
	return dr, nil
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
	// IncomingContext used from server
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		rid, okk := md[XRequestIDKey]
		if okk {
			record.AddAttrs(slog.String("rid", rid[0]))
		}
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
