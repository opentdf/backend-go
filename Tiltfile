# Tiltfile for development
# https://docs.tilt.dev/api.html

load("ext://helm_resource", "helm_resource", "helm_repo")

load("./opentdf.Tiltfile", "backend",
     "dict_to_helm_set_list", "BACKEND_CHART_TAG", "all_secrets", "CONTAINER_REGISTRY")

# backend(values=["mocks/gokas-values.yaml"])
backend()

GOKAS_DIR = os.getcwd()

docker_build(
  CONTAINER_REGISTRY + "/opentdf/gokas",
  '.',
  target='server',
)

set_values = {
    "envConfig.ecCert": all_secrets["KAS_EC_SECP256R1_CERTIFICATE"],
    "envConfig.cert": all_secrets["KAS_CERTIFICATE"],
    "envConfig.ecPrivKey": all_secrets["KAS_EC_SECP256R1_PRIVATE_KEY"],
    "envConfig.privKey": all_secrets["KAS_PRIVATE_KEY"],
    "nameOverride": "gokas",
}

helm_resource(
    "gokas",
    "oci://ghcr.io/opentdf/charts/kas",
    image_deps=[
        CONTAINER_REGISTRY + "/opentdf/gokas",
    ],
    image_keys=[
        ("image.repo", "image.tag"),
    ],
    flags=[
        "--version",
        BACKEND_CHART_TAG,
        "-f",
        "mocks/gokas-values.yaml",
        "--wait",
        "--dependency-update",
    ] + dict_to_helm_set_list(set_values),
    labels="gokas",
    resource_deps=["attributes", "keycloak"],
)

# ability to pass in custom test script with path to script as env var
# e.g.: CI=1 TEST_SCRIPT=tests/wait-and-test.sh tilt up
if "TEST_SCRIPT" in os.environ and os.environ.get("CI"):
    local_resource(
        "passed-in-test-script",
        os.environ.get("TEST_SCRIPT"),
        labels="tests",
        resource_deps=["ingress-nginx", "kas", "gokas", "keycloak-bootstrap"],
    )
