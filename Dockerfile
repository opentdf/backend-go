# multi-stage build
# reference https://docs.docker.com/develop/develop-images/multistage-build/
ARG GO_VERSION=latest
ARG ARTIFACT=gokas

# builder - executable for deployment
# reference https://hub.docker.com/_/golang
FROM golang:$GO_VERSION AS builder
WORKDIR /build/
# dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download
# source
COPY makefile ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
RUN CGO_ENABLED=1 GOOS=linux go build -v -a -installsuffix cgo -o . ./...

# tester
FROM golang:$GO_VERSION AS tester
WORKDIR /test/
COPY go.mod ./
COPY go.sum ./
COPY makefile ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY pkg/ pkg/
RUN go list -m -u all
RUN make test

# server-debug - root
FROM ubuntu:latest AS server-debug
ENV SERVICE "default"
RUN apt-get update -y && apt-get install -y softhsm opensc openssl
COPY --from=builder /build/gokas /
COPY scripts/ scripts/
COPY softhsm2-debug.conf /etc/softhsm/softhsm2.conf
RUN chmod +x /etc/softhsm
RUN mkdir -p /secrets
RUN chown 10001 /secrets
ENTRYPOINT ["/scripts/run.sh"]

# server - production
FROM ubuntu:latest AS server
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
COPY softhsm2-prod.conf /etc/softhsm/softhsm2.conf
RUN chmod +x /etc/softhsm
RUN mkdir -p /secrets
RUN chown 10001 /secrets
ENTRYPOINT ["/scripts/run.sh"]

# cli - production
FROM ubuntu:latest AS cli

ENV LOG_LEVEL=info
ENV LOG_FORMAT=text

COPY --from=builder /build/cli /
ENTRYPOINT ["/cli"]
CMD ["--help"]
