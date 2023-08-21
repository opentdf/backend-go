package main

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"log"
	//accesspdp "path_to_accesspdp_package" // Update this import with the correct package path
)

const (
	uri = "localhost:50052"
)

type accesspdp struct {
	HealthCheckRequest struct{}
}

type AccessPDPHealthzPlugin struct{}

func (a accesspdp) NewHealthClient(conection *grpc.ClientConn) {
	log.Println("NewHealthClient", conection)
}

func (p *AccessPDPHealthzPlugin) Healthz(ctx context.Context, probe bool) error {
	log.Println("Access PDP gRPC health check")

	conn, err := grpc.Dial(uri, grpc.WithInsecure())
	if err != nil {
		return err
	}
	defer conn.Close()

	client := accesspdp.NewHealthClient(conn)
	req := &accesspdp.HealthCheckRequest{}
	response, err := client.Check(ctx, req)
	if err != nil {
		return err
	}

	if response.Status == 1 {
		log.Println("--- Ping Access PDP gRPC service successful ---")
	} else {
		log.Printf("--- Ping Access PDP gRPC service failed with code %d ---", response.Status)
		return fmt.Errorf("Unable to ping Access PDP gRPC service")
	}

	return nil
}
