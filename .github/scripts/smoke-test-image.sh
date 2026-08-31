#!/usr/bin/env bash
set -euo pipefail

image=$1
trap 'docker rm -f smoke >/dev/null 2>&1 || true' EXIT

docker create --name smoke "$image" init /config/dev-idp.toml
ctx=$(mktemp -d)
mkdir -p "$ctx/config"
cp dev-idp.toml "$ctx/config/"
tar -C "$ctx" -cf - config | docker cp - smoke:/
docker start -a smoke
