# Tests

## Performance Tests

The following commands are run under `/tests`

### Setup

```shell
git clone https://github.com/pflynn-virtru/speedbump
```


### Execute PEP Performance Tests

#### Install Docker plugins

```shell
docker plugin install grafana/loki-docker-driver:2.9.1 --alias loki --grant-all-permissions
```

#### Enable Docker plugins

"Error response from daemon: error looking up logging plugin loki: plugin loki found but disabled"

```shell
docker plugin ls
docker plugin enable <ID>
```

```shell
docker-compose -f pep-performance-docker-compose.yaml -p tests up -d pep-cli
```

Grafana frontend http://localhost:3000  
admin/admin
