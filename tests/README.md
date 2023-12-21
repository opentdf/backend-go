# Tests

## Performance Tests

The following commands are run under `/tests`

### Setup

```shell
git clone https://github.com/pflynn-virtru/speedbump
```


### Execute PEP Performance Tests

```shell
docker-compose -f pep-performance-docker-compose.yaml -p tests up -d pep-cli
```
