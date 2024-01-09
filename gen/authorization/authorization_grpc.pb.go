// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.1
// source: authorization/authorization.proto

package authorization

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// AuthorizationServiceClient is the client API for AuthorizationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthorizationServiceClient interface {
	IsAuthorized(ctx context.Context, in *DecisionRequest, opts ...grpc.CallOption) (*AuthorizationDecisionResponse, error)
	GetEntitlements(ctx context.Context, in *EntitlementsRequest, opts ...grpc.CallOption) (*AuthorizationDecisionResponse, error)
}

type authorizationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthorizationServiceClient(cc grpc.ClientConnInterface) AuthorizationServiceClient {
	return &authorizationServiceClient{cc}
}

func (c *authorizationServiceClient) IsAuthorized(ctx context.Context, in *DecisionRequest, opts ...grpc.CallOption) (*AuthorizationDecisionResponse, error) {
	out := new(AuthorizationDecisionResponse)
	err := c.cc.Invoke(ctx, "/authorization.AuthorizationService/IsAuthorized", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authorizationServiceClient) GetEntitlements(ctx context.Context, in *EntitlementsRequest, opts ...grpc.CallOption) (*AuthorizationDecisionResponse, error) {
	out := new(AuthorizationDecisionResponse)
	err := c.cc.Invoke(ctx, "/authorization.AuthorizationService/GetEntitlements", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthorizationServiceServer is the server API for AuthorizationService service.
// All implementations must embed UnimplementedAuthorizationServiceServer
// for forward compatibility
type AuthorizationServiceServer interface {
	IsAuthorized(context.Context, *DecisionRequest) (*AuthorizationDecisionResponse, error)
	GetEntitlements(context.Context, *EntitlementsRequest) (*AuthorizationDecisionResponse, error)
	mustEmbedUnimplementedAuthorizationServiceServer()
}

// UnimplementedAuthorizationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAuthorizationServiceServer struct {
}

func (UnimplementedAuthorizationServiceServer) IsAuthorized(context.Context, *DecisionRequest) (*AuthorizationDecisionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsAuthorized not implemented")
}
func (UnimplementedAuthorizationServiceServer) GetEntitlements(context.Context, *EntitlementsRequest) (*AuthorizationDecisionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntitlements not implemented")
}
func (UnimplementedAuthorizationServiceServer) mustEmbedUnimplementedAuthorizationServiceServer() {}

// UnsafeAuthorizationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthorizationServiceServer will
// result in compilation errors.
type UnsafeAuthorizationServiceServer interface {
	mustEmbedUnimplementedAuthorizationServiceServer()
}

func RegisterAuthorizationServiceServer(s grpc.ServiceRegistrar, srv AuthorizationServiceServer) {
	s.RegisterService(&AuthorizationService_ServiceDesc, srv)
}

func _AuthorizationService_IsAuthorized_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DecisionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthorizationServiceServer).IsAuthorized(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authorization.AuthorizationService/IsAuthorized",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthorizationServiceServer).IsAuthorized(ctx, req.(*DecisionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthorizationService_GetEntitlements_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EntitlementsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthorizationServiceServer).GetEntitlements(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/authorization.AuthorizationService/GetEntitlements",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthorizationServiceServer).GetEntitlements(ctx, req.(*EntitlementsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthorizationService_ServiceDesc is the grpc.ServiceDesc for AuthorizationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthorizationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "authorization.AuthorizationService",
	HandlerType: (*AuthorizationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsAuthorized",
			Handler:    _AuthorizationService_IsAuthorized_Handler,
		},
		{
			MethodName: "GetEntitlements",
			Handler:    _AuthorizationService_GetEntitlements_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authorization/authorization.proto",
}
