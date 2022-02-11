# backend-go
Service providers for a protected data lifecycle

## Overview

- Helm chart with sub-charts
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
  - Others see https://github.com/tilt-dev/ctlptl

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

### Start HSM

#### SoftHSM C Module

https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2

```shell
# macOS
brew install softhsm
# get module path
brew info softhsm
# /opt/homebrew/Cellar/softhsm/2.6.1  will be  /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
export PKCS11_MODULE_PATH=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
# installs pkcs11-tool
brew install opensc
```

#### SoftHSM Keys

```shell
# enter two sets of PIN, 12345
softhsm2-util --init-token --slot 0 --label "development-token"
# verify login
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects
# create RSA keys
pkcs11-tool --module $PKCS11_MODULE_PATH --login --keypairgen --key-type rsa:2048 --id 100 --label development-rsa
# create EC keys
pkcs11-tool --module $PKCS11_MODULE_PATH --login --keypairgen --key-type EC:secp256r1 --id 200 --label development-ec


pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --slot 1232216204 --read-object --type pubkey --id 0100 -o rsa01pub.key
openssl rsa -RSAPublicKey_in -in rsa01pub.key -inform DER -outform PEM -out mykey-public.pem -RSAPublicKey_out
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
export POSTGRES_PASSWORD=mysecretpassword
export PKCS11_MODULE_PATH=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
export PKCS11_SLOT_INDEX=0
export PKCS11_PIN=12345
export PKCS11_LABEL=development-rsa
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

## Resources

KMIP  
https://github.com/ThalesGroup/kmip-go

pkcs11-tool  
https://verschlüsselt.it/generate-rsa-ecc-and-aes-keys-with-opensc-pkcs11-tool/

go-util  
https://github.com/gbolo/go-util  
https://github.com/gbolo/go-util/tree/master/pkcs11-test

## Optional

### SoftHSM Docker

https://github.com/psmiraglia/docker-softhsm

```shell
# build
docker build --file softhsm2.Dockerfile --tag softhsm2:2.5.0 .

# run
docker run -ti --rm softhsm2:2.5.0 sh -l

softhsm2-util --init-token --slot 0 --label "development-token"

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login -t

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --keypairgen --key-type rsa:2048 --id 100 --label development-rsa

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --read-object --type pubkey --label development -o development-public.der

openssl rsa -RSAPublicKey_in -in development-public.der -inform DER -outform PEM -out development-public.pem -RSAPublicKey_out

pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so --login --list-objects
```