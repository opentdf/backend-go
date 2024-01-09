.PHONY: all clean test

all: gokas

GO_MOD_LINE = $(shell head -n 1 go.mod | cut -c 8-)
GO_MOD_NAME = ${GO_MOD_LINE}
CONF_PATH = ${GO_MOD_NAME}/internal/conf
VERSION = $(shell cat VERSION)
BUILD_TIME = $(shell date +'%Y-%m-%d_%T')
SHA1 = $(shell git rev-parse HEAD)
MAIN_FILE = cmd/microservice/main.go

# TODO: Fix swagger generation
# update-doc: 
# 	swag init -d api
gokas: $(shell find . -name "*.go" -and -not -path '*/dist*' -and -not -path '*/coverage*' -and -not -path '*/node_modules*')
	go build -ldflags '-X ${CONF_PATH}.Version=${VERSION} -X ${CONF_PATH}.Sha1=${SHA1} -X ${CONF_PATH}.BuildTime=${BUILD_TIME}' -o gokas ${MAIN_FILE}
go-plugins:
	go build -buildmode=plugin -o="plugins/" plugins/**
clean:
	rm -f gokas
test: gokas
	go vet ./...
	go test -bench=. -benchmem ./...
