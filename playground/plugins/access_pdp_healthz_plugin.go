package main

import "log"

func Healthz() {
	log.SetPrefix("Healthz: ")

	//logger.debug("Access PDP gRPC health check")
	//channel = grpc.insecure_channel(uri)
	//stub = accesspdp_pb2_grpc.HealthStub(channel)
	//req = accesspdp_pb2.HealthCheckRequest()
	//response = stub.Check(req)
	//
	//if response.status == 1:
	//logger.debug("--- Ping Access PDP gRPC service successful --- ")
	//else:
	//logger.debug(
	//	f"--- Ping Access PDP gRPC service failed with code {response.status} --- "
	//)
	//raise Error("Unable to be ping Access PDP gRPC service")
}
