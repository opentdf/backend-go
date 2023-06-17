# Read more here: https://hub.docker.com/_/golang
FROM golang:1.20 as build

ENV GO111MODULE=on \
    CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# TODO add go.sum
COPY go.mod ./
RUN go mod download && go mod verify

COPY base.go ./
RUN go build -o main .

# Move to /dist directory as the place for resulting binary folder
WORKDIR /app

# Copy binary from build to main folder
RUN cp /build/main .

CMD ["/build/main"]
