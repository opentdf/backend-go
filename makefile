.PHONY: all clean test

all: gokas go-plugins
go-plugins: plugins/audit_hooks.so

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

plugins/audit_hooks.so: $(shell find plugins -name "*.go")
	go build -buildmode=plugin -o="plugins/" plugins/**

clean:
	rm -f gokas
	find plugins -type f -name '*.so' | xargs rm

test: gokas
	go vet ./...
	go test -bench=. -benchmem ./...
