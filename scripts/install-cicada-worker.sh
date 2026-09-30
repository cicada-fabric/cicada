#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  CICADA_CONTROL_URL=https://hub.example.org \
  CICADA_MACHINE_ID=node-lab-a \
  scripts/install-cicada-worker.sh

Build the Node agent from this checkout (or use CICADA_BINARY_PATH), persist
its local identity under a private state directory, then run the real agent in
the foreground. The Node prints a 10-minute pairing code. In the authenticated
Android Client, preview the exact Node and confirm it explicitly. This script
does not pass a Hub bearer or provider key to the Hub and opens no inbound port.

Environment:
  CICADA_CONTROL_URL       Hub URL; HTTPS remotely, loopback HTTP for local use
  CICADA_MACHINE_ID        Stable Node ID (defaults to hostname -s)
  CICADA_MACHINE_NAME      Display name (defaults to the Node ID)
  CICADA_NODE_STATE_DIR    Private local state directory
  CICADA_SOURCE_DIR        CICADA checkout (defaults to this script's checkout)
  CICADA_BINARY_PATH       Optional already-built local cicada binary
EOF
}

die() {
  printf 'cicada Node setup: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || die "unknown argument: $1"

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

need hostname
need install
need mktemp
need codex
codex queue --help >/dev/null 2>&1 || die "installed Codex CLI must support 'codex queue'"

control_url="${CICADA_CONTROL_URL:-}"
[[ -n "$control_url" ]] || die "set CICADA_CONTROL_URL to the Hub URL"
node_id="${CICADA_MACHINE_ID:-$(hostname -s)}"
node_name="${CICADA_MACHINE_NAME:-$node_id}"
[[ "$node_id" =~ ^[A-Za-z0-9._-]+$ ]] || die "CICADA_MACHINE_ID may contain only letters, numbers, dot, underscore, and dash"
[[ -n "$node_name" && ${#node_name} -le 128 ]] || die "CICADA_MACHINE_NAME must contain 1..128 characters"
[[ "$(id -u)" -ne 0 ]] || die "run as the local Codex user, not root"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
source_dir="${CICADA_SOURCE_DIR:-$repo_root}"
binary_path="${CICADA_BINARY_PATH:-}"
build_dir=""
if [[ -z "$binary_path" ]]; then
  [[ -f "$source_dir/cicada-go/go.mod" ]] || die "CICADA_SOURCE_DIR must point to a CICADA checkout"
  need go
  build_dir="$(mktemp -d "${TMPDIR:-/tmp}/cicada-node-build.XXXXXXXX")"
  trap 'rm -rf "$build_dir"' EXIT
  (cd "$source_dir/cicada-go" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/cicada" ./cmd/cicada)
  binary_path="$build_dir/cicada"
fi
[[ -x "$binary_path" ]] || die "CICADA_BINARY_PATH is not an executable binary"

user_home="${HOME:-$(pwd)}"
state_dir="${CICADA_NODE_STATE_DIR:-${XDG_STATE_HOME:-$user_home/.local/state}/cicada/node}"
[[ "$state_dir" = /* ]] || die "CICADA_NODE_STATE_DIR must be an absolute path"
install -d -m 0700 "$state_dir"
chmod 0700 "$state_dir"

printf 'Hub URL: %s\nNode ID: %s\nNode state: %s (mode 0700)\n' "$control_url" "$node_id" "$state_dir"
printf 'Starting outbound-only Node agent. Pairing code is short-lived; confirm it in the authenticated Android Client.\n'
"$binary_path" machine agent \
  --id "$node_id" \
  --name "$node_name" \
  --control-url "$control_url" \
  --state-dir "$state_dir" \
  --relay-only
