# syntax=docker/dockerfile:1
ARG GOLANG_VERSION=1.20
FROM golang:${GOLANG_VERSION} AS builder
WORKDIR /build/
# dependencies
COPY go.mod go.sum ./
RUN go mod download
# copy Go files - add new package to this list
COPY *.go ./
COPY /cmd/ ./cmd/
COPY /internal/ ./internal/
COPY /pkg/ ./pkg/
COPY VERSION .
# build optimized
RUN CGO_ENABLED=1 GOOS=linux go build \
    -v -a -installsuffix cgo \
    -o . \
    -ldflags="-s -w -X cmd/microservice/main.Version=$(cat <VERSION)" \
    ./...
# TODO build debug

# server - debug
FROM ubuntu:latest AS production-debug
ENV SERVER_LOG_LEVEL "DEBUG"
ENTRYPOINT ["/microservice"]
# TODO copy debug build from builder
COPY --from=builder /build/microservice /

# server - production
FROM scratch AS production
# Server
ENV SERVER_PORT "8080"
ENV SERVER_LOG_LEVEL "INFO"
ENV SERVER_PUBLIC_NAME ""
ENV SERVER_ROOT_PATH "/"
# OIDC
ENV OIDC_CLIENT_ID ""
ENV OIDC_CLIENT_SECRET ""
ENV OIDC_CONFIGURATION_URL ""
# PKCS#11
ENV PKCS11_MODULE_PATH ""
ENV PKCS11_PIN ""
ENV PKCS11_SLOT_INDEX ""
ENV PKCS11_LABEL_PUBKEY_RSA ""
ENV PKCS11_LABEL_PUBKEY_EC ""
ENTRYPOINT ["/microservice"]
COPY --from=builder /build/microservice /