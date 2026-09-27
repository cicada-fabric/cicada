#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_root="${CICADA_CLIENT_HUB_DATA:-${repo_root}/.cicada-data/client-hub-dev}"
image_name="${CICADA_CLIENT_HUB_IMAGE:-cicada-codex:client-hub-only-dev}"
container_name="${CICADA_CLIENT_HUB_CONTAINER:-cicada-client-hub-dev}"
host_port="${CICADA_CLIENT_HUB_PORT:-8787}"

if docker container inspect "${container_name}" >/dev/null 2>&1; then
  printf 'Container %s already exists. No container or image changes were made.\n' "${container_name}" >&2
  exit 1
fi

umask 077
mkdir -p "${data_root}/state" "${data_root}/workspaces"
token_file="${data_root}/management-token"
if [[ ! -s "${token_file}" ]]; then
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n' >"${token_file}"
  printf '\n' >>"${token_file}"
fi
chmod 0600 "${token_file}"

"${repo_root}/scripts/build-hub-image.sh" \
  --image "${image_name}" \
  --metadata-file "${data_root}/build.json"
image_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"]["id"])' "${data_root}/build.json")"
runtime_env="$(mktemp "${data_root}/.runtime-env.XXXXXXXX")"
trap 'rm -f "$runtime_env"' EXIT
printf 'CICADA_API_TOKEN=%s\n' "$(tr -d '\n' <"${token_file}")" >"${runtime_env}"

docker run --rm -d \
  --name "${container_name}" \
  -p "127.0.0.1:${host_port}:8787" \
  -v "${data_root}/state:/state" \
  -v "${data_root}/workspaces:/workspace" \
  --env-file "${runtime_env}" \
  "${image_id}" \
  serve --host 0.0.0.0 --port 8787 >/dev/null
host_port="$(docker port "${container_name}" 8787/tcp | cut -d : -f 2)"
python3 - "$host_port" <<'PY'
import sys
import time
import urllib.error
import urllib.request

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(60):
    try:
        with opener.open("http://127.0.0.1:" + sys.argv[1] + "/healthz", timeout=2) as response:
            if response.status == 200:
                break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(0.5)
else:
    raise SystemExit("Hub did not become healthy; inspect the named development container")
PY

printf 'Hub: http://127.0.0.1:%s\n' "${host_port}"
printf 'Management token file (local bootstrap only): %s\n' "${token_file}"
printf 'Client contract: %s/docs/client-hub-v1.openapi.yaml\n' "${repo_root}"
printf 'Wire reference: %s/docs/client-hub-wire-v1.md\n' "${repo_root}"
