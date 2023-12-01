# Tiltfile for development
# https://docs.tilt.dev/api.html

load("./opentdf.Tiltfile", "backend",
     "dict_to_helm_set_list", "BACKEND_CHART_TAG", "all_secrets")

backend()

GOKAS_DIR = os.getcwd()
# BACKEND_CHART_TAG = os.environ.get("BACKEND_LATEST_VERSION", "1.4.2")

docker_build(
    CONTAINER_REGISTRY + "/opentdf/gokas",
    context=GOKAS_DIR
)

set_values = {
    "kas.envConfig.ecCert": all_secrets["KAS_EC_SECP256R1_CERTIFICATE"],
    "kas.envConfig.cert": all_secrets["KAS_CERTIFICATE"],
    "kas.envConfig.ecPrivKey": all_secrets["KAS_EC_SECP256R1_PRIVATE_KEY"],
    "kas.envConfig.privKey": all_secrets["KAS_PRIVATE_KEY"],
}

helm_resource(
    "gokas",
    "oci://ghcr.io/opentdf/charts/kas",
    image_deps=[
        CONTAINER_REGISTRY + "/opentdf/gokas",
    ],
    image_keys=[
        ("kas.image.repo", "kas.image.tag"),
    ]
    flags=[
        "--version",
        BACKEND_CHART_TAG,
        "-f",
        "mocks/gokas-values.yaml",
        "--wait",
        "--dependency-update",
    ] + dict_to_helm_set_list(set_values),
    labels="backend",
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
