// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.1
// source: entitlements/entitlements.proto

package entitlements

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

// EntitlementsServiceClient is the client API for EntitlementsService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type EntitlementsServiceClient interface {
	// Any fields in the request message which are not bound by the path pattern automatically become (optional) HTTP query parameters. Assume the following definition of the request message:
	GetEntitlements(ctx context.Context, in *GetEntitlementsRequest, opts ...grpc.CallOption) (*GetEntitlementsResponse, error)
}

type entitlementsServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewEntitlementsServiceClient(cc grpc.ClientConnInterface) EntitlementsServiceClient {
	return &entitlementsServiceClient{cc}
}

func (c *entitlementsServiceClient) GetEntitlements(ctx context.Context, in *GetEntitlementsRequest, opts ...grpc.CallOption) (*GetEntitlementsResponse, error) {
	out := new(GetEntitlementsResponse)
	err := c.cc.Invoke(ctx, "/entitlements.EntitlementsService/GetEntitlements", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EntitlementsServiceServer is the server API for EntitlementsService service.
// All implementations must embed UnimplementedEntitlementsServiceServer
// for forward compatibility
type EntitlementsServiceServer interface {
	// Any fields in the request message which are not bound by the path pattern automatically become (optional) HTTP query parameters. Assume the following definition of the request message:
	GetEntitlements(context.Context, *GetEntitlementsRequest) (*GetEntitlementsResponse, error)
	mustEmbedUnimplementedEntitlementsServiceServer()
}

// UnimplementedEntitlementsServiceServer must be embedded to have forward compatible implementations.
type UnimplementedEntitlementsServiceServer struct {
}

func (UnimplementedEntitlementsServiceServer) GetEntitlements(context.Context, *GetEntitlementsRequest) (*GetEntitlementsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEntitlements not implemented")
}
func (UnimplementedEntitlementsServiceServer) mustEmbedUnimplementedEntitlementsServiceServer() {}

// UnsafeEntitlementsServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to EntitlementsServiceServer will
// result in compilation errors.
type UnsafeEntitlementsServiceServer interface {
	mustEmbedUnimplementedEntitlementsServiceServer()
}

func RegisterEntitlementsServiceServer(s grpc.ServiceRegistrar, srv EntitlementsServiceServer) {
	s.RegisterService(&EntitlementsService_ServiceDesc, srv)
}

func _EntitlementsService_GetEntitlements_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetEntitlementsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EntitlementsServiceServer).GetEntitlements(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/entitlements.EntitlementsService/GetEntitlements",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(EntitlementsServiceServer).GetEntitlements(ctx, req.(*GetEntitlementsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// EntitlementsService_ServiceDesc is the grpc.ServiceDesc for EntitlementsService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var EntitlementsService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "entitlements.EntitlementsService",
	HandlerType: (*EntitlementsServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetEntitlements",
			Handler:    _EntitlementsService_GetEntitlements_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "entitlements/entitlements.proto",
}
