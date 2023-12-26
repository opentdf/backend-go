#!/usr/bin/env bash

set -x

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

cd "$APP_DIR" || exit 1
if ! pip install -r requirements.txt; then
  echo "Failed to install python deps for roundtrip test"
  exit 1
fi

_wait-for() {
  echo "[INFO] In retry loop for quickstarted opentdf backend..."
  limit=5
  for i in $(seq 1 $limit); do
    if curl --show-error --fail --insecure http://localhost:65432/api/kas; then
      return 0
    fi
    if [[ $i == "$limit" ]]; then
      echo "[WARN] Breaking _wait-for loop as we are at limit"
      break
    fi
    sleep_for=$((10 + i * i * 2))
    echo "[INFO] retrying in ${sleep_for} seconds... ( ${i} / $limit ) ..."
    sleep ${sleep_for}
  done
  echo "[ERROR] Couldn't connect to opentdf backend"
  exit 1
}

if ! _wait-for; then
  exit 1
fi

rm -rf sample.{out,tdf,txt}
echo hello-world >sample.txt
if ! python3 ./tdf.py encrypt sample.txt sample.tdf; then
  echo ERROR encrypt failure
  exit 1
fi

if ! python3 ./tdf.py decrypt sample.tdf sample.out; then
  echo ERROR decrypt failure
  exit 1
fi

echo INFO Successful round trip!
