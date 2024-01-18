// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.1
// source: attributes/attributes.proto

package attributes

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

// AttributesServiceClient is the client API for AttributesService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AttributesServiceClient interface {
	GetAttribute(ctx context.Context, in *GetAttributeRequest, opts ...grpc.CallOption) (*GetAttributeResponse, error)
	GetAttributeGroup(ctx context.Context, in *GetAttributeGroupRequest, opts ...grpc.CallOption) (*GetAttributeGroupResponse, error)
	ListAttributes(ctx context.Context, in *ListAttributesRequest, opts ...grpc.CallOption) (*ListAttributesResponse, error)
	ListAttributeGroups(ctx context.Context, in *ListAttributeGroupsRequest, opts ...grpc.CallOption) (*ListAttributeGroupsResponse, error)
	CreateAttribute(ctx context.Context, in *CreateAttributeRequest, opts ...grpc.CallOption) (*CreateAttributeResponse, error)
	CreateAttributeGroup(ctx context.Context, in *CreateAttributeGroupRequest, opts ...grpc.CallOption) (*CreateAttributeGroupResponse, error)
	UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error)
	UpdateAttributeGroup(ctx context.Context, in *UpdateAttributeGroupRequest, opts ...grpc.CallOption) (*UpdateAttributeGroupResponse, error)
	DeleteAttribute(ctx context.Context, in *DeleteAttributeRequest, opts ...grpc.CallOption) (*DeleteAttributeResponse, error)
	DeleteAttributeGroup(ctx context.Context, in *DeleteAttributeGroupRequest, opts ...grpc.CallOption) (*DeleteAttributeGroupResponse, error)
}

type attributesServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAttributesServiceClient(cc grpc.ClientConnInterface) AttributesServiceClient {
	return &attributesServiceClient{cc}
}

func (c *attributesServiceClient) GetAttribute(ctx context.Context, in *GetAttributeRequest, opts ...grpc.CallOption) (*GetAttributeResponse, error) {
	out := new(GetAttributeResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/GetAttribute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) GetAttributeGroup(ctx context.Context, in *GetAttributeGroupRequest, opts ...grpc.CallOption) (*GetAttributeGroupResponse, error) {
	out := new(GetAttributeGroupResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/GetAttributeGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) ListAttributes(ctx context.Context, in *ListAttributesRequest, opts ...grpc.CallOption) (*ListAttributesResponse, error) {
	out := new(ListAttributesResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/ListAttributes", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) ListAttributeGroups(ctx context.Context, in *ListAttributeGroupsRequest, opts ...grpc.CallOption) (*ListAttributeGroupsResponse, error) {
	out := new(ListAttributeGroupsResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/ListAttributeGroups", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) CreateAttribute(ctx context.Context, in *CreateAttributeRequest, opts ...grpc.CallOption) (*CreateAttributeResponse, error) {
	out := new(CreateAttributeResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/CreateAttribute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) CreateAttributeGroup(ctx context.Context, in *CreateAttributeGroupRequest, opts ...grpc.CallOption) (*CreateAttributeGroupResponse, error) {
	out := new(CreateAttributeGroupResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/CreateAttributeGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) UpdateAttribute(ctx context.Context, in *UpdateAttributeRequest, opts ...grpc.CallOption) (*UpdateAttributeResponse, error) {
	out := new(UpdateAttributeResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/UpdateAttribute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) UpdateAttributeGroup(ctx context.Context, in *UpdateAttributeGroupRequest, opts ...grpc.CallOption) (*UpdateAttributeGroupResponse, error) {
	out := new(UpdateAttributeGroupResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/UpdateAttributeGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) DeleteAttribute(ctx context.Context, in *DeleteAttributeRequest, opts ...grpc.CallOption) (*DeleteAttributeResponse, error) {
	out := new(DeleteAttributeResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/DeleteAttribute", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *attributesServiceClient) DeleteAttributeGroup(ctx context.Context, in *DeleteAttributeGroupRequest, opts ...grpc.CallOption) (*DeleteAttributeGroupResponse, error) {
	out := new(DeleteAttributeGroupResponse)
	err := c.cc.Invoke(ctx, "/attributes.AttributesService/DeleteAttributeGroup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AttributesServiceServer is the server API for AttributesService service.
// All implementations must embed UnimplementedAttributesServiceServer
// for forward compatibility
type AttributesServiceServer interface {
	GetAttribute(context.Context, *GetAttributeRequest) (*GetAttributeResponse, error)
	GetAttributeGroup(context.Context, *GetAttributeGroupRequest) (*GetAttributeGroupResponse, error)
	ListAttributes(context.Context, *ListAttributesRequest) (*ListAttributesResponse, error)
	ListAttributeGroups(context.Context, *ListAttributeGroupsRequest) (*ListAttributeGroupsResponse, error)
	CreateAttribute(context.Context, *CreateAttributeRequest) (*CreateAttributeResponse, error)
	CreateAttributeGroup(context.Context, *CreateAttributeGroupRequest) (*CreateAttributeGroupResponse, error)
	UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error)
	UpdateAttributeGroup(context.Context, *UpdateAttributeGroupRequest) (*UpdateAttributeGroupResponse, error)
	DeleteAttribute(context.Context, *DeleteAttributeRequest) (*DeleteAttributeResponse, error)
	DeleteAttributeGroup(context.Context, *DeleteAttributeGroupRequest) (*DeleteAttributeGroupResponse, error)
	mustEmbedUnimplementedAttributesServiceServer()
}

// UnimplementedAttributesServiceServer must be embedded to have forward compatible implementations.
type UnimplementedAttributesServiceServer struct {
}

func (UnimplementedAttributesServiceServer) GetAttribute(context.Context, *GetAttributeRequest) (*GetAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) GetAttributeGroup(context.Context, *GetAttributeGroupRequest) (*GetAttributeGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAttributeGroup not implemented")
}
func (UnimplementedAttributesServiceServer) ListAttributes(context.Context, *ListAttributesRequest) (*ListAttributesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAttributes not implemented")
}
func (UnimplementedAttributesServiceServer) ListAttributeGroups(context.Context, *ListAttributeGroupsRequest) (*ListAttributeGroupsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAttributeGroups not implemented")
}
func (UnimplementedAttributesServiceServer) CreateAttribute(context.Context, *CreateAttributeRequest) (*CreateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) CreateAttributeGroup(context.Context, *CreateAttributeGroupRequest) (*CreateAttributeGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAttributeGroup not implemented")
}
func (UnimplementedAttributesServiceServer) UpdateAttribute(context.Context, *UpdateAttributeRequest) (*UpdateAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) UpdateAttributeGroup(context.Context, *UpdateAttributeGroupRequest) (*UpdateAttributeGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAttributeGroup not implemented")
}
func (UnimplementedAttributesServiceServer) DeleteAttribute(context.Context, *DeleteAttributeRequest) (*DeleteAttributeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAttribute not implemented")
}
func (UnimplementedAttributesServiceServer) DeleteAttributeGroup(context.Context, *DeleteAttributeGroupRequest) (*DeleteAttributeGroupResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAttributeGroup not implemented")
}
func (UnimplementedAttributesServiceServer) mustEmbedUnimplementedAttributesServiceServer() {}

// UnsafeAttributesServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AttributesServiceServer will
// result in compilation errors.
type UnsafeAttributesServiceServer interface {
	mustEmbedUnimplementedAttributesServiceServer()
}

func RegisterAttributesServiceServer(s grpc.ServiceRegistrar, srv AttributesServiceServer) {
	s.RegisterService(&AttributesService_ServiceDesc, srv)
}

func _AttributesService_GetAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).GetAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/GetAttribute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).GetAttribute(ctx, req.(*GetAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_GetAttributeGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAttributeGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).GetAttributeGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/GetAttributeGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).GetAttributeGroup(ctx, req.(*GetAttributeGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_ListAttributes_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAttributesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).ListAttributes(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/ListAttributes",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).ListAttributes(ctx, req.(*ListAttributesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_ListAttributeGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAttributeGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).ListAttributeGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/ListAttributeGroups",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).ListAttributeGroups(ctx, req.(*ListAttributeGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_CreateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).CreateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/CreateAttribute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).CreateAttribute(ctx, req.(*CreateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_CreateAttributeGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAttributeGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).CreateAttributeGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/CreateAttributeGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).CreateAttributeGroup(ctx, req.(*CreateAttributeGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_UpdateAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).UpdateAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/UpdateAttribute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).UpdateAttribute(ctx, req.(*UpdateAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_UpdateAttributeGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAttributeGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).UpdateAttributeGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/UpdateAttributeGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).UpdateAttributeGroup(ctx, req.(*UpdateAttributeGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_DeleteAttribute_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAttributeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).DeleteAttribute(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/DeleteAttribute",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).DeleteAttribute(ctx, req.(*DeleteAttributeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AttributesService_DeleteAttributeGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAttributeGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AttributesServiceServer).DeleteAttributeGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/attributes.AttributesService/DeleteAttributeGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AttributesServiceServer).DeleteAttributeGroup(ctx, req.(*DeleteAttributeGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AttributesService_ServiceDesc is the grpc.ServiceDesc for AttributesService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AttributesService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "attributes.AttributesService",
	HandlerType: (*AttributesServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAttribute",
			Handler:    _AttributesService_GetAttribute_Handler,
		},
		{
			MethodName: "GetAttributeGroup",
			Handler:    _AttributesService_GetAttributeGroup_Handler,
		},
		{
			MethodName: "ListAttributes",
			Handler:    _AttributesService_ListAttributes_Handler,
		},
		{
			MethodName: "ListAttributeGroups",
			Handler:    _AttributesService_ListAttributeGroups_Handler,
		},
		{
			MethodName: "CreateAttribute",
			Handler:    _AttributesService_CreateAttribute_Handler,
		},
		{
			MethodName: "CreateAttributeGroup",
			Handler:    _AttributesService_CreateAttributeGroup_Handler,
		},
		{
			MethodName: "UpdateAttribute",
			Handler:    _AttributesService_UpdateAttribute_Handler,
		},
		{
			MethodName: "UpdateAttributeGroup",
			Handler:    _AttributesService_UpdateAttributeGroup_Handler,
		},
		{
			MethodName: "DeleteAttribute",
			Handler:    _AttributesService_DeleteAttribute_Handler,
		},
		{
			MethodName: "DeleteAttributeGroup",
			Handler:    _AttributesService_DeleteAttributeGroup_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "attributes/attributes.proto",
}
