# multi-stage build
# reference https://docs.docker.com/develop/develop-images/multistage-build/
ARG GO_VERSION=latest

# builder - executable for deployment
# reference https://hub.docker.com/_/golang
FROM golang:$GO_VERSION as builder
WORKDIR /build/
COPY go.mod ./
COPY go.sum ./
COPY makefile ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
RUN make gokas

# tester
FROM golang:$GO_VERSION as tester
WORKDIR /test/
COPY go.mod ./
COPY go.sum ./
COPY makefile ./
COPY cmd/ cmd/
COPY mock/ mock/
COPY pkg/ pkg/
# dependency
RUN go list -m -u all
#  static analysis
RUN go vet ./...
# test and benchmark
RUN go test -bench=. -benchmem ./...
# race condition
RUN make gokas

# server-debug - root
FROM ubuntu:latest as server-debug
ENV SERVICE "default"
RUN apt-get update -y && apt-get install -y softhsm opensc openssl
COPY --from=builder /build/gokas /
COPY scripts/ scripts/
ENTRYPOINT ["/scripts/run.sh"]

# server - production
FROM ubuntu:latest as server
ENV SERVICE "default"
# Server
ENV SERVER_ROOT_PATH "/"
ENV SERVER_PORT "4020"
ENV SERVER_PUBLIC_NAME ""
ENV SERVER_LOG_LEVEL "INFO"
## trailing / is required
ENV OIDC_ISSUER ""
ENV OIDC_SERVER_URL ""
ENV OIDC_AUTHORIZATION_URL ""
ENV OIDC_TOKEN_URL ""
ENV OIDC_CONFIGURATION_URL ""
# PKCS#11
ENV PKCS11_MODULE_PATH ""
ENV PKCS11_PIN ""
ENV PKCS11_SLOT_INDEX ""
ENV PKCS11_LABEL_PUBKEY_RSA ""
ENV PKCS11_LABEL_PUBKEY_EC ""
RUN apt-get update -y && apt-get install -y softhsm opensc openssl

COPY --from=builder /build/gokas /
COPY scripts/ /scripts/
ENTRYPOINT ["/scripts/run.sh"]
