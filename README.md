# backend-go
Service providers for a protected data lifecycle

## Overview

- Helm chart with subcharts
- Multi-stage Dockerfile for build, testing, and deployment
- Fast developer workflow

## Prerequisites

- Install Docker
    - see https://docs.docker.com/get-docker/

- Install kubectl
    - On macOS via Homebrew: `brew install kubectl`
    - Others see https://kubernetes.io/docs/tasks/tools/

- Install minikube
    - On macOS via Homebrew: `brew install minikube`
    - Others see https://minikube.sigs.k8s.io/docs/start/

- Install Helm
    - On macOS via Homebrew: `brew install helm`
    - Others see https://helm.sh/docs/intro/install/

- Install Tilt
    - On macOS via Homebrew: `brew install tilt-dev/tap/tilt`
    - Others see https://docs.tilt.dev/install.html

- Install ctlptl
  - On macOS via Homebrew: `brew install tilt-dev/tap/ctlptl`
  - Others see https://github.com/kubernetes/examples/blob/master/guidelines.md

## Development

### Create cluster

#### minikube

```shell
# create
ctlptl create cluster minikube --registry=ctlptl-registry --kubernetes-version=v1.22.2
# delete
ctlptl delete cluster minikube
```

#### kind

```shell
# create
ctlptl create cluster kind --registry=ctlptl-registry
# delete
ctlptl delete cluster kind-kind
```

### Install ingress

```shell
helm repo add nginx-stable https://helm.nginx.com/stable
helm repo update
helm install ex nginx-stable/nginx-ingress
```

### Start database

```shell
mkdir -p data
docker run \
    --detach \
    --publish 0.0.0.0:5432:5432 \
    --volume data:/var/lib/postgresql/data \
    --env POSTGRES_PASSWORD=mysecretpassword \
    --env PGDATA=/var/lib/postgresql/data/pgdata \
    postgres
```

### Start services

```shell
tilt up
```

### Start monolith service (outside kubernetes)

```shell
export POSTGRES_HOST=localhost
export POSTGRES_DATABASE=postgres
export POSTGRES_USER=postgres
```

## References

### Helm
https://helm.sh/docs/chart_template_guide/subcharts_and_globals/  
https://faun.pub/helm-chart-how-to-create-helm-charts-from-kubernetes-k8s-yaml-from-scratch-d64901e36850  
https://github.com/kubernetes/examples/blob/master/guidelines.md  

### Go
https://github.com/powerman/go-monolith-example  
https://github.com/getkin/kin-openapi  

### Docker
https://docs.docker.com/develop/develop-images/multistage-build/  
https://medium.com/@lizrice/non-privileged-containers-based-on-the-scratch-image-a80105d6d341  

### Tilt
https://dev.to/ndrean/rails-on-kubernetes-with-minikube-and-tilt-25ka  

### PostgreSQL
https://dev.to/kushagra_mehta/postgresql-with-go-in-2021-3dfg  
https://stackoverflow.com/questions/24319662/from-inside-of-a-docker-container-how-do-i-connect-to-the-localhost-of-the-mach/24326540#24326540  

### minikube
https://minikube.sigs.k8s.io/docs/handbook/host-access/  

### OIDC
https://github.com/coreos/go-oidc  

### Ingress
https://docs.nginx.com/nginx-ingress-controller/installation/installation-with-helm/  

## TODO
- add ingress
- add more services to support popular pet store example 

## Troubleshooting

### inside a container

```shell
apt-get update -y
apt-get install -y netcat
nc -vz host.minikube.internal 5432

helm install postgresql bitnami/postgresql

apt-get install postgresql-client
pg_isready --dbname=postgres --host=host.minikube.internal --port=5432 --username=postgres
pg_isready --dbname=postgres --host=ex-postgresql --port=5432 --username=postgres
```
