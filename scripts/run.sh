#! /bin/bash
# Use ./scripts/run.sh [host]
# Parameters:
#   Optional parameter: port or host to expose. Defaults to 8000 
#
# Environment variables:
#   PKCS11_PIN
#     - SECRET
#     - local PIN for pkcs11. will be generated if not present
#   KAS_PRIVATE_KEY
#     - SECRET
#     - Private key (SECRET) KAS uses to certify responses.
#   KAS_CERTIFICATE
#     - SECRET
#     - Public key KAS clients can use to validate responses.
#   ATTR_AUTHORITY_HOST
#     - OpenTDF Attribute service host, or other compliant authority
#   ATTR_AUTHORITY_CERTIFICATE
#     - The public key used to validate responses from ATTR_AUTHORITY_HOST.

#   Not Implemented or used Yet
#   OIDC_SERVER_URL
#     - FIXME
#     - List of allowed prefixes for OIDC tokens
#   LOGLEVEL
#     - Verbosity of default log handler. Should recognize python log levels
#   JSON_LOGGER
#     - if to enable json mode of log output. 'true' enabled json output
#   KAS_EC_SECP256R1_PRIVATE_KEY
#     - (SECRET) private key of curve secp256r1, KAS uses to certify responses.
#     - required for nanoTDF
#   KAS_EC_SECP256R1_CERTIFICATE
#     - The public key of curve secp256r1, KAS clients can use
#       to validate responses.
#     - required for nanoTDF
#   AUDIT_ENABLED
#   CA_CERT_PATH
#     - 
#
#   Maybe will not implement?
#   USE_OIDC
#   CLIENT_CERT_PATH
#   CLIENT_KEY_PATH
#   V2_SAAS_ENABLED
#   LEGACY_NANOTDF_IV

e() {
  echo ERROR "${@}"
  exit 1
}

l() {
  echo INFO "${@}"
}

# Configure and validate HOST variable
# This should be of the form [port] or [https://host:port/], for example
if [ -z $1]; then
  HOST=https://localhost:8000/
elif [[ $1 == *" "* ]]; then
  e "Invalid hostname: [$1]"
elif [[ $1 == http?:* ]]; then
  HOST="$1":8000
elif [[ $1 == http?:*:* ]]; then
  HOST="$1"
elif [[ $1 =~ ^[0-9]+$ ]]; then
  HOST=https://localhost:$1/
else
  e "Invalid hostname or port: [$1]"
fi
export HOST

: "${PKCS11_SLOT_INDEX:=0}"
: "${PKCS11_TOKEN_LABEL:=development-token}"
# FIXME random or error out if not set
: "${PKCS11_PIN:=12345}"
: "${PKCS11_SO_PIN:=12345}"
: "${PKCS11_MODULE_PATH:=/lib/softhsm/libsofthsm2.so}"
: "${PKCS11_LABEL_PUBKEY_RSA:=development-rsa-kas}"
: "${PKCS11_LABEL_PUBKEY_EC:=development-ec-kas}"

# Configure softhsm. This is used to store secrets in an HSM compatible way
# softhsm2-util --init-token --slot 0 --label "development-token" --pin $PKCS11_PIN --so-pin $HSM_SO_PIN
echo $PKCS11_PIN | softhsm2-util --init-token --slot "${PKCS11_SLOT_INDEX}" --label "${PKCS11_TOKEN_LABEL}" ||
  e "Unable to use softhsm to init [--slot ${PKCS11_SLOT_INDEX} --label ${PKCS11_TOKEN_LABEL}]"
# verify login
pkcs11-tool --login --show-info --list-objects ||
  e "Unable to list objects with pkcs11-tool"

if [ -z ${KAS_PRIVATE_KEY}]; then
  l "Creating new KAS private key - missing parameter KAS_PRIVATE_KEY"
  openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-private.pem --type privkey --id 100 --label development-rsa-kas
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-cert.pem --type cert --id 100 --label development-rsa-kas
elif [ -z ${KAS_CERTIFICATE}]; then
  e "Missing KAS_CERTIFICATE"
else
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object <(echo ${KAS_PRIVATE_KEY}) --type privkey --id 100 --label development-rsa-kas
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object <(echo ${KAS_CERTIFICATE}) --type cert --id 100 --label development-rsa-kas
fi

if [ -z ${KAS_EC_SECP256R1_PRIVATE_KEY}]; then
  l "Creating new KAS private key - missing parameter KAS_EC_SECP256R1_PRIVATE_KEY"
  # create EC key and cert
  openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365
  # import EC key to PKCS
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-private.pem --type privkey --id 200 --label development-ec-kas
  # import EC cert to PKCS
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object kas-ec-cert.pem --type cert --id 200 --label development-ec-kas
elif [ -z ${KAS_EC_SECP256R1_CERTIFICATE}]; then
  e "Missing KAS_EC_SECP256R1_CERTIFICATE"
else
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object <(echo $KAS_EC_SECP256R1_PRIVATE_KEY) --type privkey --id 200 --label development-ec-kas
  echo $PKCS11_PIN | pkcs11-tool --module $PKCS11_MODULE_PATH --login --write-object <(echo $KAS_EC_SECP256R1_CERTIFICATE) --type cert --id 200 --label development-ec-kas
fi

/build/gokas
