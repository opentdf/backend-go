# multi-stage build
# reference https://docs.docker.com/develop/develop-images/multistage-build/
ARG GO_VERSION=latest

# builder - executable for deployment
# reference https://hub.docker.com/_/golang
FROM golang:$GO_VERSION as builder
# reference https://medium.com/@lizrice/non-privileged-containers-based-on-the-scratch-image-a80105d6d341
RUN useradd -u 10001 scratchuser
WORKDIR /build/
COPY go.* ./
COPY cmd/ cmd/
COPY pkg/ pkg/
RUN CGO_ENABLED=0 GOOS=linux go build -v -a -installsuffix cgo -o . ./...

# tester
FROM golang:$GO_VERSION as tester
WORKDIR /test/
COPY go.* ./
COPY cmd/ cmd/
COPY pkg/ pkg/
# dependency
RUN go list -m -u all
#  static analysis
RUN go vet ./...
# test and benchmark
RUN go test -bench=. -benchmem ./...
# race condition
RUN CGO_ENABLED=1 GOOS=linux go build -v -a -race -installsuffix cgo -o . ./...

# server-debug - root
FROM ubuntu:latest as server-debug
EXPOSE 8080
ENTRYPOINT ["/microservice"]
ENV SERVICE "default"
COPY --from=builder /build/microservice /

# server - production
FROM scratch as server
USER scratchuser
EXPOSE 8080
ENTRYPOINT ["/microservice"]
ENV SERVICE "default"
COPY --from=builder /build/microservice /
COPY --from=builder /etc/passwd /etc/passwd