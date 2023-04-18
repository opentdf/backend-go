# Plugins in Golang

This tests out using [the golang plugin module](https://pkg.go.dev/plugin) to load additional modules at runtime. We intend to use this to dynamically load middleware modules, enabling upsert and ACM plugins in a manner similar to virtru's python KAS.

The app works by having a library loaded at runtime, then loading an object within it, mimicking the loading and usage process we intend to use for the new service.

## Sample plugin (no dockerfile):

Build and run:

```
cd playground/base
go build . -o main
cd ../plugins
go build -buildmode=plugin ./a.go
go build -buildmode=plugin ./b.go
cd ../
./base/main --plugin plugin/a.so  --plugin plugin/b.so
```

## Sample with Dockerfile

Validate it works with no plugins

```
cd base
docker build -t base-golang-app .
docker run -it --rm --name base-running-app base-golang-app
```
Note fails need to specify plugin

```
cd ../plugins
docker build -t golang-app .
docker run -it --rm --name running-app golang-app
```

Should print:

```
Injected A
Injected B
```
