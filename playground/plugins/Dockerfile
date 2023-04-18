FROM golang:1.20 as build

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# TODO add go.sum
COPY go.mod ./
RUN go mod download && go mod verify

COPY a.go ./
RUN go build -buildmode=plugin ./a.go

COPY b.go ./
RUN go build -buildmode=plugin ./b.go

WORKDIR /dist

FROM base-golang-app as app

RUN cp /build/a.so /build/b.so .

CMD ["/build/main"]

