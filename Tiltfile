# Tiltfile for development
# https://docs.tilt.dev/api.html

# troubleshoot target='server-debug'
docker_build('microservice', '.', target='server')

# helm
k8s_yaml(helm('helm', 'ex'))
