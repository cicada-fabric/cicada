#!/usr/bin/env bash
set -euo pipefail

data_root="${CICADA_DATA_ROOT:-/gpu1-share/data/cicada}"
image="${CICADA_IMAGE:-cicada-codex:dev}"
export CICADA_UID="${CICADA_UID:-$(id -u)}"
export CICADA_GID="${CICADA_GID:-$(id -g)}"

./scripts/bootstrap-cicada.sh
docker compose build control
docker image inspect "$image" --format 'Built {{.RepoTags}} ({{.Id}})'

install -d -m 0755 "$data_root/images"
archive="$data_root/images/cicada-codex-dev.tar"
docker save --output "$archive" "$image"
sha256sum "$archive" | tee "$archive.sha256"
printf 'Image archive: %s\n' "$archive"
