/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Binary client is an example client.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/opentdf/backend-go/pkg/access"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/health"
)

func callVersion(c access.AccessServiceClient) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.Info(ctx, &access.InfoRequest{})
	if err != nil {
		slog.Info("AppInfo", "err", err)
	} else {
		slog.Info("AppInfo", "version", r.Version)
	}
}

func main() {
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	address := ":5000"

	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())

	if err != nil {
		slog.Error("grpc.Dial(%q): %v", address, err)
		os.Exit(1)
	}
	defer conn.Close()

	informerClient := access.NewAccessServiceClient(conn)

	for {
		callVersion(informerClient)
		time.Sleep(time.Second)
	}
}
