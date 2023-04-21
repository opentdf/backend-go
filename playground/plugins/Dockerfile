# Stage 1: Build
FROM golang:1.20 AS build

ENV GO111MODULE=on \
    CGO_ENABLED=1\
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -buildmode=plugin -o a.so a.go && \
    go build -buildmode=plugin -o b.so b.go && \
    go build -o main base.go
RUN chmod a+x /app


# Stage 2: Application
#FROM base-golang-app as app
FROM scratch
COPY --from=build /lib /lib
COPY --from=build /lib/x86_64-linux-gnu /lib64
COPY --from=build /lib64 /lib64
COPY --from=build /app/a.so /a.so
COPY --from=build /app/b.so /b.so
COPY --from=build /app/main /main

CMD ["/main", "--plugin", "a.so", "--plugin", "b.so"]