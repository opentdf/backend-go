# Tiltfile for development
# https://docs.tilt.dev/api.html

load("./opentdf.Tiltfile", "opentdf_cluster_with_ingress")

opentdf_cluster_with_ingress(start_frontend=False)

# ability to pass in custom test script with path to script as env var
# e.g.: CI=1 TEST_SCRIPT=tests/wait-and-test.sh tilt up
if "TEST_SCRIPT" in os.environ and os.environ.get("CI"):
    local_resource(
        "passed-in-test-script",
        os.environ.get("TEST_SCRIPT"),
        labels="tests",
        resource_deps=["ingress-nginx", "keycloak-bootstrap", "kas"],
    )
