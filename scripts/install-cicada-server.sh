#!/usr/bin/env bash
set -Eeuo pipefail

# Install or update a Cicada Control host. The script is intentionally usable
# through `curl | bash`; it downloads a pinned source archive, creates the
# operator-owned data root, and starts only the Control service.

die() {
  printf 'cicada server installer: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

repo_url="${CICADA_REPOSITORY:-https://github.com/cicada-fabric/cicada}"
ref="${CICADA_REF:-main}"
install_dir="${CICADA_INSTALL_DIR:-/opt/cicada}"
data_root="${CICADA_DATA_ROOT:-/var/lib/cicada}"
api_port="${CICADA_API_PORT:-8787}"
image="${CICADA_IMAGE:-cicada-codex:dev}"
source_dir="${CICADA_SOURCE_DIR:-}"
force_update="${CICADA_UPDATE:-0}"

[[ "$api_port" =~ ^[0-9]+$ ]] && ((api_port >= 1 && api_port <= 65535)) || die "CICADA_API_PORT must be 1..65535"
[[ "$install_dir" = /* && "$data_root" = /* ]] || die "install and data paths must be absolute"

need curl
need install
need awk
need od
need tar
need find
need mktemp
need tr
need seq
need sleep

compose=(docker compose)
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  compose=(docker-compose)
else
  die "Docker Compose is required (install Docker Engine with the Compose plugin)"
fi

if [[ -z "$source_dir" ]]; then
  if [[ -f "docker-compose.yml" && -d "docker" && -d "cicada-go" ]]; then
    source_dir="$(pwd)"
  else
    repo_slug="${repo_url#https://github.com/}"
    repo_slug="${repo_slug#http://github.com/}"
    repo_slug="${repo_slug%.git}"
    [[ "$repo_slug" != */* || "$repo_slug" = */*/* ]] && die "CICADA_REPOSITORY must be a GitHub owner/repository URL"
    temp_root="$(mktemp -d)"
    trap 'rm -rf "$temp_root"' EXIT
    archive_url="${CICADA_ARCHIVE_URL:-https://codeload.github.com/${repo_slug}/tar.gz/${ref}}"
    curl --fail --location --retry 3 --silent --show-error "$archive_url" | tar -xzf - -C "$temp_root"
    source_dir="$(find "$temp_root" -mindepth 1 -maxdepth 1 -type d -print -quit)"
    [[ -n "$source_dir" && -f "$source_dir/docker-compose.yml" ]] || die "downloaded archive does not contain docker-compose.yml"
  fi
else
  [[ -f "$source_dir/docker-compose.yml" && -d "$source_dir/docker" && -d "$source_dir/cicada-go" ]] || die "CICADA_SOURCE_DIR is not a Cicada checkout"
fi

if [[ -e "$install_dir/docker-compose.yml" && "$force_update" != 1 ]]; then
  source_dir="$install_dir"
else
  install -d -m 0755 "$install_dir"
  source_real="$(cd "$source_dir" && pwd -P)"
  install_real="$(cd "$install_dir" && pwd -P)"
  if [[ "$source_real" != "$install_real" ]]; then
    cp -a "$source_dir/." "$install_dir/"
  fi
fi

install -d -m 0755 \
  "$data_root" \
  "$data_root/state/control" \
  "$data_root/state/worker" \
  "$data_root/state/telegram" \
  "$data_root/workspaces" \
  "$data_root/logs/control" \
  "$data_root/logs/worker" \
  "$data_root/logs/telegram" \
  "$data_root/images" \
  "$data_root/vendor"
install -d -m 0700 "$data_root/secrets"

env_file="$data_root/secrets/cicada.env"
api_key="${CICADA_MODEL_API_KEY:-${API_KEY:-}}"
if [[ -n "${CICADA_MODEL_API_KEY_FILE:-}" ]]; then
  [[ -r "$CICADA_MODEL_API_KEY_FILE" ]] || die "CICADA_MODEL_API_KEY_FILE is not readable"
  api_key="$(<"$CICADA_MODEL_API_KEY_FILE")"
  api_key="${api_key%$'\n'}"
  api_key="${api_key%$'\r'}"
fi
[[ "$api_key" != *$'\n'* && "$api_key" != *$'\r'* ]] || die "model API key must not contain a newline"
api_token="${CICADA_API_TOKEN:-}"

if [[ -s "$env_file" ]]; then
  existing_token="$(awk -F= '$1 == "CICADA_API_TOKEN" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
  if [[ -z "$api_token" && -n "$existing_token" ]]; then
    api_token="$existing_token"
  fi
fi

if [[ ! -s "$env_file" && -z "$api_key" ]]; then
  if [[ -r /dev/tty ]]; then
    printf 'Cicada needs the model API key for Codex workers (input is not echoed): ' >/dev/tty
    IFS= read -r -s api_key </dev/tty
    printf '\n' >/dev/tty
  else
    die "set CICADA_MODEL_API_KEY (or API_KEY) when running non-interactively"
  fi
fi

if [[ -z "$api_token" ]]; then
  api_token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
fi

export CICADA_DATA_ROOT="$data_root"
export CICADA_IMAGE="$image"
export CICADA_API_PORT="$api_port"
export API_KEY="$api_key"
export CICADA_API_TOKEN="$api_token"
"$install_dir/scripts/bootstrap-cicada.sh" >/dev/null

# Existing secret files are intentionally preserved. Add the generated Control
# token when an older installation did not have one yet, and repair an empty
# token entry so the advertised bearer token always matches Compose auth.
if awk -F= '$1 == "CICADA_API_TOKEN" { found=1; if (length(substr($0, index($0, "=") + 1)) > 0) value=substr($0, index($0, "=") + 1); exit } END { exit(found && value != "" ? 0 : 1) }' "$env_file"; then
  api_token="$(awk -F= '$1 == "CICADA_API_TOKEN" { print substr($0, index($0, "=") + 1); exit }' "$env_file")"
else
  token_tmp="${env_file}.tmp.$$"
  if awk -F= '$1 == "CICADA_API_TOKEN" { found=1; next } { print } END { if (!found) exit 2 }' "$env_file" > "$token_tmp"; then
    printf 'CICADA_API_TOKEN=%s\n' "$api_token" >> "$token_tmp"
  else
    printf 'CICADA_API_TOKEN=%s\n' "$api_token" >> "$env_file"
    rm -f "$token_tmp"
  fi
  if [[ -s "$token_tmp" ]]; then
    chmod 0600 "$token_tmp"
    mv "$token_tmp" "$env_file"
  fi
  chmod 0600 "$env_file"
fi

# Give workers a file containing only the bearer token. The Compose env file
# also contains model credentials and is intentionally not suitable for
# passing to a worker installer as CICADA_API_TOKEN_FILE.
token_file="$data_root/secrets/control.token"
umask 077
printf '%s\n' "$api_token" > "$token_file"
chmod 0600 "$token_file"

compose_env="$install_dir/.env"
umask 077
{
  printf 'CICADA_DATA_ROOT=%s\n' "$data_root"
  printf 'CICADA_IMAGE=%s\n' "$image"
  printf 'CICADA_API_PORT=%s\n' "$api_port"
} > "$compose_env"
chmod 0600 "$compose_env"

cd "$install_dir"
"${compose[@]}" build control
"${compose[@]}" up -d control

health_url="http://127.0.0.1:${api_port}/healthz"
ready=0
for _ in $(seq 1 60); do
  if curl --fail --silent --show-error "$health_url" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
((ready == 1)) || die "Control did not become healthy; inspect: ${compose[*]} logs control"

printf '\nCicada Control is running.\n'
printf 'Install directory: %s\n' "$install_dir"
printf 'Data and secrets:  %s\n' "$data_root"
printf 'Panel (local):     http://127.0.0.1:%s/\n' "$api_port"
printf 'Remote tunnel:     ssh -N -L %s:127.0.0.1:%s user@server\n' "$api_port" "$api_port"
printf 'Bearer token file: %s (keep private; do not paste it into chat)\n' "$token_file"
printf 'Compose secrets:    %s (contains the model credential; keep private)\n' "$env_file"
printf 'Worker enrollment: set CICADA_CONTROL_URL and CICADA_API_TOKEN_FILE to the bearer token file, then run install-cicada-worker.sh.\n'
