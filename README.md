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
docker run \
    --detach \
    --publish 5432:5432 \
    --env POSTGRES_HOST_AUTH_METHOD=trust \
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
# crease RSA key and cert
openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
# crease EC key and cert
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365
# import RSA key to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-private.pem --type privkey --id 100 --label development-rsa-kas
# import RSA cert to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-cert.pem --type cert --id 100 --label development-rsa-kas
# import EC key to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-private.pem --type privkey --id 200 --label development-ec-kas
# import EC cert to PKCS
pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-cert.pem --type cert --id 200 --label development-ec-kas
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
export PKCS11_LABEL_PUBKEY_RSA=development-rsa-kas
export PKCS11_LABEL_PUBKEY_EC=development-ec-kas
export PRIVATE_KEY_RSA_PATH=../../kas-private.pem
export OIDC_ISSUER=https://keycloak.opentdf.us/auth/realms/opentdf-realm
export OIDC_CLIENT_ID=632cb24a-580b-4a0f-9682-b45ff159774f
export OIDC_CLIENT_SECRET=myentitlementssecret
```

## Test

Check public key service is working
```shell
curl http://127.0.0.1:8080/kas_public_key
```

Check entitlements service is working
```shell
curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:8080/v2/claims
curl -I -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJub25jZSI6IjRELU1sT29zclBFWURKOXhfU0lHZko4RFNEU0tuR3k4YzRvbmhTR2FVOW8iLCJhbGciOiJSUzI1NiIsIng1dCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyIsImtpZCI6ImpTMVhvMU9XRGpfNTJ2YndHTmd2UU8yVnpNYyJ9.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8wN2Y1ZjYwYi1mZWFiLTRmNTEtOTA5NS0yNzg1YTg3NzkyODEvIiwiaWF0IjoxNjUzMDY5MzEwLCJuYmYiOjE2NTMwNjkzMTAsImV4cCI6MTY1MzA3NDYyNCwiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IkFTUUEyLzhUQUFBQWxtNUpqUUxpVCtxNkhHVEIzdW0veTdocGxxWEw1N3R2eGRVZFhLZzdUTjQ9IiwiYW1yIjpbInB3ZCJdLCJhcHBfZGlzcGxheW5hbWUiOiJsb2NhbGhvc3QtYWJhY3VzIiwiYXBwaWQiOiIxOTViMzcxNS1lN2VmLTQ3OWItOTI3NC1kNzlkYjViNzYzNGQiLCJhcHBpZGFjciI6IjAiLCJmYW1pbHlfbmFtZSI6IkZseW5uIiwiZ2l2ZW5fbmFtZSI6IlBhdWwiLCJpZHR5cCI6InVzZXIiLCJpcGFkZHIiOiI3My4xMzMuMTgwLjI1NSIsIm5hbWUiOiJQYXVsIEZseW5uIiwib2lkIjoiYmYxZWZhYjAtMDE2Mi00NGY4LTk5ODctMjc0MGNhNzYzNTJmIiwicGxhdGYiOiI1IiwicHVpZCI6IjEwMDNCRkZEQTY2REMwRDUiLCJyaCI6IjAuQVZrQUNfYjFCNnYtVVUtUWxTZUZxSGVTZ1FNQUFBQUFBQUFBd0FBQUFBQUFBQUJaQUtRLiIsInNjcCI6Im9wZW5pZCBwcm9maWxlIFVzZXIuUmVhZCBlbWFpbCIsInN1YiI6Ikdhcm9qMkZsb3lCNkpDdnpLZGczbWZXNjFMQ0xJTXlXRWgzTWt0d01TMXciLCJ0ZW5hbnRfcmVnaW9uX3Njb3BlIjoiTkEiLCJ0aWQiOiIwN2Y1ZjYwYi1mZWFiLTRmNTEtOTA5NS0yNzg1YTg3NzkyODEiLCJ1bmlxdWVfbmFtZSI6InBhdWxAYXJrYXZvLmNvbSIsInVwbiI6InBhdWxAYXJrYXZvLmNvbSIsInV0aSI6Ik1QZWZNenZGcTB5aENaT2g1SVd1QUEiLCJ2ZXIiOiIxLjAiLCJ3aWRzIjpbIjYyZTkwMzk0LTY5ZjUtNDIzNy05MTkwLTAxMjE3NzE0NWUxMCIsImI3OWZiZjRkLTNlZjktNDY4OS04MTQzLTc2YjE5NGU4NTUwOSJdLCJ4bXNfc3QiOnsic3ViIjoibnlZRnVTZWs5emlReWRMZkdqcFZKbnVFUzBzamtHS1R5WlgzeDdMUlREcyJ9LCJ4bXNfdGNkdCI6MTUxMTY2ODg1NH0.Wt3CS7TSQfO-gN_DAE6GlM0lpKawaxZgp_Q3x083QDK5jdBc_J6hiGKE-HGi8wmeMr0NNYuOXKgJp7CK5IqXuexlEezBLKPKxVvYPxsAYdrpwd8jDcWyklewCUNKEvkBRkc8CKlMAGUwEuPbVjGWRYAmfkakpTolRJEJABE7DCmAbLTqQWzI0Ya6U-zlMAJ-tzStgXplrxx26DLI28gZQIJX0A0gERyNvGOrQeb7gFdUvw7_R1AiJVVeVHo-YgPsHJAxA-_xeqHNoSzdc13MNZSj_UtnxAR-BkYsA2nE7QE17w8M1HUobkT9s9ecmnkKV8PR08obiIRd2oshZ-FGQQ" http://127.0.0.1:8080/definitions/groups
```

### Test Environments

opentdf.us
```env
OIDC_CLIENT_ID=opentdf-entitlements;OIDC_ISSUER=https://keycloak.opentdf.us/auth/realms/opentdf-realm;PKCS11_LABEL_PUBKEY_EC=development-ec-kas;PKCS11_LABEL_PUBKEY_RSA=development-rsa-kas;PKCS11_MODULE_PATH=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so;PKCS11_PIN=12345;PKCS11_SLOT_INDEX=0;POSTGRES_DATABASE=postgres
```

microsoftonline.com
```env
OIDC_CLIENT_ID=opentdf-entitlements;OIDC_ISSUER=https://login.microsoftonline.com/07f5f60b-feab-4f51-9095-2785a8779281/v2.0;PKCS11_LABEL_PUBKEY_EC=development-ec-kas;PKCS11_LABEL_PUBKEY_RSA=development-rsa-kas;PKCS11_MODULE_PATH=/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so;PKCS11_PIN=12345;PKCS11_SLOT_INDEX=0;POSTGRES_DATABASE=postgres
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

pkcs11-tool --module /usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so --login --list-objects
```
