#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_root="${CICADA_CLIENT_HUB_DATA:-${repo_root}/.cicada-data/client-hub-dev}"
image_name="${CICADA_CLIENT_HUB_IMAGE:-cicada-codex:client-hub-dev}"
container_name="${CICADA_CLIENT_HUB_CONTAINER:-cicada-client-hub-dev}"
host_port="${CICADA_CLIENT_HUB_PORT:-8787}"

umask 077
mkdir -p "${data_root}/state" "${data_root}/workspaces"
token_file="${data_root}/management-token"
if [[ ! -s "${token_file}" ]]; then
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"${token_file}"
  printf '\n' >>"${token_file}"
  chmod 0600 "${token_file}"
fi

build_proxy="${CICADA_BUILD_PROXY:-http://127.0.0.1:7890}"
docker build --network=host \
  --build-arg "CICADA_UID=$(id -u)" \
  --build-arg "CICADA_GID=$(id -g)" \
  --build-arg "HTTP_PROXY=${build_proxy}" \
  --build-arg "HTTPS_PROXY=${build_proxy}" \
  -f "${repo_root}/docker/Dockerfile" \
  -t "${image_name}" "${repo_root}"

if docker container inspect "${container_name}" >/dev/null 2>&1; then
  printf 'Container %s already exists. Stop it before replacing its image.\n' "${container_name}" >&2
  exit 1
fi

docker run --rm -d \
  --name "${container_name}" \
  -p "127.0.0.1:${host_port}:8787" \
  -v "${data_root}/state:/state" \
  -v "${data_root}/workspaces:/workspace" \
  -e "CICADA_API_TOKEN=$(tr -d '\n' <"${token_file}")" \
  --entrypoint cicada "${image_name}" \
  serve --host 0.0.0.0 --port 8787 >/dev/null

printf 'Hub: http://127.0.0.1:%s\n' "${host_port}"
printf 'Management token file (local bootstrap only): %s\n' "${token_file}"
printf 'Client contract: %s/docs/client-hub-v1.openapi.yaml\n' "${repo_root}"
printf 'Wire reference: %s/docs/client-hub-wire-v1.md\n' "${repo_root}"
