# Tiltfile for development -- runs backend with python kas, ingress, and go-kas with seperate kas chart
# https://docs.tilt.dev/api.html

load("ext://helm_resource", "helm_resource", "helm_repo")

load("./opentdf.Tiltfile", "opentdf_cluster_with_ingress", "seperate_gokas")

os.environ.get("GOKAS_SEPARATE")

GOKAS_SEPARATE=os.environ.get("GOKAS_SEPARATE", True)

if not GOKAS_SEPARATE:
   opentdf_cluster_with_ingress()
else:
    opentdf_cluster_with_ingress(gokas=False)
    seperate_gokas()


# ability to pass in custom test script with path to script as env var
# e.g.: CI=1 TEST_SCRIPT=tests/wait-and-test.sh tilt up
if "TEST_SCRIPT" in os.environ and os.environ.get("CI"):
    local_resource(
        "passed-in-test-script",
        os.environ.get("TEST_SCRIPT"),
        labels="tests",
        resource_deps=["ingress-nginx", "kas", "gokas", "keycloak-bootstrap"],
    )
