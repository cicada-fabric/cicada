#!/usr/bin/env bash
set -Eeuo pipefail

# Install a headless Cicada machine agent and, when systemd is available,
# keep it running as a service. A worker makes outbound requests to Control;
# it does not expose a listening port.

die() {
  printf 'cicada worker installer: %s\n' "$*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

repo_url="${CICADA_REPOSITORY:-https://github.com/cicada-fabric/cicada}"
ref="${CICADA_REF:-main}"
version="${CICADA_VERSION:-}"
binary_url="${CICADA_BINARY_URL:-}"
binary_sha256="${CICADA_BINARY_SHA256:-}"
binary_path="${CICADA_BINARY_PATH:-}"
install_dir="${CICADA_INSTALL_DIR:-}"
control_url="${CICADA_CONTROL_URL:-}"
machine_id="${CICADA_MACHINE_ID:-$(hostname -s)}"
machine_name="${CICADA_MACHINE_NAME:-$machine_id}"
workspace_root="${CICADA_WORKSPACE_ROOT:-}"
interval="${CICADA_MACHINE_HEARTBEAT_SECONDS:-30}"
run_user="${CICADA_RUN_USER:-${SUDO_USER:-$(id -un)}}"
service_name="${CICADA_SERVICE_NAME:-cicada-worker}"
token="${CICADA_API_TOKEN:-}"
token_file="${CICADA_API_TOKEN_FILE:-}"
model_key="${CICADA_MODEL_API_KEY:-${API_KEY:-}}"
model_key_file="${CICADA_MODEL_API_KEY_FILE:-}"
source_dir="${CICADA_SOURCE_DIR:-}"

need install
need curl
need hostname
need awk
need mktemp
need tar
need find

[[ -n "$control_url" ]] || die "set CICADA_CONTROL_URL to the Control HTTPS URL"
[[ "$control_url" =~ ^https?://[^/]+/?$ ]] || die "CICADA_CONTROL_URL must be an absolute URL without a path"
[[ "$machine_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "CICADA_MACHINE_ID may contain only letters, numbers, dot, underscore, and dash"
[[ "$service_name" =~ ^[A-Za-z0-9._-]+$ ]] || die "CICADA_SERVICE_NAME contains unsupported characters"
[[ "$interval" =~ ^[0-9]+$ ]] && ((interval >= 1)) || die "CICADA_MACHINE_HEARTBEAT_SECONDS must be at least 1"

if [[ -n "$token_file" ]]; then
  [[ -r "$token_file" ]] || die "CICADA_API_TOKEN_FILE is not readable"
  token="$(<"$token_file")"
  token="${token%$'\n'}"
  token="${token%$'\r'}"
fi
if [[ -z "$token" && "${CICADA_ALLOW_ANONYMOUS:-0}" != 1 ]]; then
  die "set CICADA_API_TOKEN_FILE (preferred) or CICADA_API_TOKEN; use CICADA_ALLOW_ANONYMOUS=1 only for an intentionally public Control"
fi
[[ "$token" != *$'\n'* && "$token" != *$'\r'* && "$token" != *[[:space:]]* ]] || die "Control token must be a single non-whitespace value"

if [[ -n "$model_key_file" ]]; then
  [[ -r "$model_key_file" ]] || die "CICADA_MODEL_API_KEY_FILE is not readable"
  model_key="$(<"$model_key_file")"
  model_key="${model_key%$'\n'}"
  model_key="${model_key%$'\r'}"
fi
[[ "$model_key" != *$'\n'* && "$model_key" != *$'\r'* ]] || die "model API key must not contain a newline"

if [[ -z "$install_dir" ]]; then
  if [[ "$(id -u)" -eq 0 ]]; then
    install_dir=/usr/local/bin
  else
    user_bin="${XDG_BIN_HOME:-}"
    if [[ -z "$user_bin" ]]; then
      home_dir="${HOME:-$(pwd)}"
      user_bin="$home_dir/.local/bin"
    fi
    install_dir="$user_bin"
  fi
fi
[[ "$install_dir" = /* ]] || die "CICADA_INSTALL_DIR must be an absolute path"
binary_path="${binary_path:-$install_dir/cicada}"
workspace_root="${workspace_root:-$(pwd)/cicada-workspaces/$machine_id}"
[[ "$workspace_root" = /* ]] || die "CICADA_WORKSPACE_ROOT must be an absolute path"

temp_root="$(mktemp -d)"
trap 'rm -rf "$temp_root"' EXIT

if [[ -n "$binary_url" ]]; then
  curl --fail --location --retry 3 --silent --show-error "$binary_url" -o "$temp_root/cicada"
  if [[ -n "$binary_sha256" ]]; then
    need sha256sum
    printf '%s  %s\n' "$binary_sha256" "$temp_root/cicada" | sha256sum -c -
  fi
  built_binary="$temp_root/cicada"
elif [[ -n "$version" ]]; then
  [[ "$version" =~ ^[0-9A-Za-z.-]+$ ]] || die "CICADA_VERSION contains unsupported characters"
  need uname
  release_arch="$(uname -m)"
  case "$release_arch" in
    x86_64|amd64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) die "no published Linux binary for architecture: $release_arch" ;;
  esac
  repo_slug="${repo_url#https://github.com/}"
  repo_slug="${repo_slug#http://github.com/}"
  repo_slug="${repo_slug%.git}"
  [[ "$repo_slug" != */* || "$repo_slug" = */*/* ]] && die "CICADA_REPOSITORY must be a GitHub owner/repository URL"
  release_url="https://github.com/${repo_slug}/releases/download/v${version}/cicada-linux-${release_arch}"
  curl --fail --location --retry 3 --silent --show-error "$release_url" -o "$temp_root/cicada"
  if [[ -n "$binary_sha256" ]]; then
    need sha256sum
    printf '%s  %s\n' "$binary_sha256" "$temp_root/cicada" | sha256sum -c -
  fi
  built_binary="$temp_root/cicada"
else
  if [[ -z "$source_dir" ]]; then
    if [[ -f "cicada-go/go.mod" ]]; then
      source_dir="$(pwd)"
    else
      repo_slug="${repo_url#https://github.com/}"
      repo_slug="${repo_slug#http://github.com/}"
      repo_slug="${repo_slug%.git}"
      [[ "$repo_slug" != */* || "$repo_slug" = */*/* ]] && die "CICADA_REPOSITORY must be a GitHub owner/repository URL"
      archive_url="${CICADA_ARCHIVE_URL:-https://codeload.github.com/${repo_slug}/tar.gz/${ref}}"
      curl --fail --location --retry 3 --silent --show-error "$archive_url" | tar -xzf - -C "$temp_root"
      source_dir="$(find "$temp_root" -mindepth 1 -maxdepth 1 -type d -print -quit)"
    fi
  fi
  [[ -f "$source_dir/cicada-go/go.mod" ]] || die "source checkout is missing cicada-go/go.mod"
  if ! command -v go >/dev/null 2>&1; then
    die "Go is required to build from source; set CICADA_BINARY_URL to a release asset instead"
  fi
  (cd "$source_dir/cicada-go" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$temp_root/cicada" ./cmd/cicada)
  built_binary="$temp_root/cicada"
fi

install -d -m 0755 "$install_dir"
install -m 0755 "$built_binary" "$binary_path"
install -d -m 0750 "$workspace_root"

if [[ "$(id -u)" -eq 0 && -n "$run_user" ]]; then
  id "$run_user" >/dev/null 2>&1 || die "CICADA_RUN_USER does not exist: $run_user"
  chown "$run_user" "$workspace_root"
fi

if ! command -v codex >/dev/null 2>&1; then
  printf 'warning: official Codex CLI was not found; Codex harness jobs will stay unavailable until it is installed for %s\n' "$run_user" >&2
fi

if [[ "$(id -u)" -eq 0 && -d /etc/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
  runtime_dir=/etc/cicada
  env_path="$runtime_dir/${service_name}.env"
  unit_path="/etc/systemd/system/${service_name}.service"
  install -d -m 0700 "$runtime_dir"
  umask 077
  systemd_quote() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '"%s"' "$value"
  }
  {
    printf 'CICADA_CONTROL_URL='; systemd_quote "$control_url"; printf '\n'
    printf 'CICADA_MACHINE_ID='; systemd_quote "$machine_id"; printf '\n'
    printf 'CICADA_MACHINE_NAME='; systemd_quote "$machine_name"; printf '\n'
    printf 'CICADA_WORKSPACE_ROOT='; systemd_quote "$workspace_root"; printf '\n'
    if [[ -n "$token" ]]; then printf 'CICADA_API_TOKEN='; systemd_quote "$token"; printf '\n'; fi
    if [[ -n "$model_key" ]]; then printf 'API_KEY='; systemd_quote "$model_key"; printf '\n'; fi
  } > "$env_path"
  chmod 0600 "$env_path"
  cat > "$unit_path" <<EOF
[Unit]
Description=Cicada machine agent (${machine_id})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${run_user}
EnvironmentFile=${env_path}
ExecStart=${binary_path} machine agent --interval ${interval}s
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${workspace_root}

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$unit_path"
  systemctl daemon-reload
  systemctl enable --now "${service_name}.service"
  printf 'Cicada worker service: %s.service\n' "$service_name"
  printf 'Worker environment:    %s (mode 0600)\n' "$env_path"
else
  printf 'Binary installed: %s\n' "$binary_path"
  printf 'Run the agent: %s machine agent --interval %ss\n' "$binary_path" "$interval"
  printf 'Set CICADA_CONTROL_URL, CICADA_MACHINE_ID, CICADA_WORKSPACE_ROOT and CICADA_API_TOKEN before starting it.\n'
fi

printf 'Machine %s is configured for outbound Control polling.\n' "$machine_id"
