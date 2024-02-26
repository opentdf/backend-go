#!/bin/bash

export GOCACHE=/tmp/go-build
# Add your existing script commands here
# For example:
 echo "Running my /scripts/run.sh"

 ls -l

 ./scripts/run.sh

 echo "====== Done my run.sh, start running tests"

 ls -l

 cd test
 go vet ./...
 go test ./...