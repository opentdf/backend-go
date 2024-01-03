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
	"fmt"
	"log"
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
		fmt.Println("AppInfo: _, ", err)
	} else {
		fmt.Println("AppInfo: ", r.Version)
	}
}

func main() {
	flag.Parse()
	fmt.Println("lesgo")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	address := ":5000"

	fmt.Println("dialing")
	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())

	if err != nil {
		log.Fatalf("grpc.Dial(%q): %v", address, err)
	}
	defer conn.Close()

	fmt.Println("infoermering")
	informerClient := access.NewAccessServiceClient(conn)

	for {
		fmt.Println("callVersion")
		callVersion(informerClient)
		time.Sleep(time.Second)
	}
}
