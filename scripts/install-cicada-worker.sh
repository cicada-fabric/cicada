#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage:
  CICADA_CONTROL_URL=https://hub.example.org \
  CICADA_MACHINE_ID=node-lab-a \
  scripts/install-cicada-worker.sh [--mode relay|managed]

Build the Node agent from this checkout (or use CICADA_BINARY_PATH), persist
its local identity under a private state directory, then run the real agent in
the foreground. Mode defaults to relay. Select --mode managed only when this
Node should also process authorized Worker jobs and Monitor notices. The Node
prints a 10-minute pairing code. In the authenticated Android Client, preview
the exact Node and confirm it explicitly. This script does not pass a Hub
bearer or provider key to the Hub, automatically join a Thread or Group, or
approve the Node, and it opens no inbound port.

Modes:
  relay       Fabric message delivery only; safe default, no Worker polling
  managed     Also process Node-authorized Worker jobs and Monitor notices

Environment:
  CICADA_CONTROL_URL       Hub URL; HTTPS remotely, loopback HTTP for local use
  CICADA_MACHINE_ID        Stable Node ID (defaults to hostname -s)
  CICADA_MACHINE_NAME      Display name (defaults to the Node ID)
  CICADA_NODE_STATE_DIR    Private local state directory
  CICADA_SOURCE_DIR        CICADA checkout (defaults to this script's checkout)
  CICADA_BINARY_PATH       Optional already-built local cicada binary
  CICADA_NODE_PQTLS_CONFIG Optional private PQ config; requires the optional
                           Linux amd64 PQ package via CICADA_BINARY_PATH
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

mode='relay'
while (($#)); do
  case "$1" in
    --mode)
      (($# >= 2)) || die "--mode requires relay or managed"
      mode="$2"
      shift 2
      ;;
    --mode=*)
      mode="${1#--mode=}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done
case "$mode" in
  relay|managed) ;;
  *) die "mode must be relay or managed" ;;
esac

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

validate_state_directory() {
  local path="$1" remaining component prefix=''
  [[ "$path" = /* && "$path" != / && "$path" != */ ]] || die "Node state directory must be an absolute canonical path below root"
  remaining="${path#/}"
  while [[ -n "$remaining" ]]; do
    component="${remaining%%/*}"
    [[ -n "$component" && "$component" != . && "$component" != .. ]] || die "Node state directory must not contain empty, dot or dot-dot components"
    prefix="$prefix/$component"
    [[ ! -L "$prefix" ]] || die "Node state directory must not contain a symlink or symlink ancestor"
    [[ ! -e "$prefix" || -d "$prefix" ]] || die "Node state path components must be directories"
    if [[ "$remaining" = */* ]]; then remaining="${remaining#*/}"; else remaining=''; fi
  done
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
  [[ -z "${CICADA_NODE_PQTLS_CONFIG:-}" ]] || die "PQ transport requires the optional package via CICADA_BINARY_PATH; automatic CGO0 build is unavailable"
  [[ -f "$source_dir/cicada-go/go.mod" ]] || die "CICADA_SOURCE_DIR must point to a CICADA checkout"
  need go
  build_dir="$(mktemp -d "${TMPDIR:-/tmp}/cicada-node-build.XXXXXXXX")"
  trap 'rm -rf "$build_dir"' EXIT
  (cd "$source_dir/cicada-go" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$build_dir/cicada" ./cmd/cicada)
  binary_path="$build_dir/cicada"
fi
[[ -x "$binary_path" ]] || die "CICADA_BINARY_PATH is not an executable binary"
if [[ -n "${CICADA_NODE_PQTLS_CONFIG:-}" ]]; then
  [[ -z "${LD_LIBRARY_PATH:-}" && -z "${LD_PRELOAD:-}" ]] || die "PQ package requires its relative loader path; remove ambient LD_LIBRARY_PATH/LD_PRELOAD"
  package_root="$(cd "$(dirname "$binary_path")/.." && pwd -P)"
  [[ -f "$package_root/BUILD-METADATA.json" && -f "$package_root/SHA256SUMS" &&
     -f "$package_root/lib/libssl.so.3" && -f "$package_root/lib/libcrypto.so.3" ]] || die "PQ binary must come from the complete optional package"
  need sha256sum
  (cd "$package_root" && sha256sum --check --status SHA256SUMS) || die "PQ package checksum verification failed"
fi

user_home="${HOME:-$(pwd)}"
state_dir="${CICADA_NODE_STATE_DIR:-${XDG_STATE_HOME:-$user_home/.local/state}/cicada/node}"
validate_state_directory "$state_dir"
install -d -m 0700 "$state_dir"
validate_state_directory "$state_dir"
chmod 0700 "$state_dir"

printf 'Hub URL: %s\nNode ID: %s\nNode mode: %s\nNode state: %s (mode 0700)\n' "$control_url" "$node_id" "$mode" "$state_dir"
printf 'Starting outbound-only Node agent. Pairing code is short-lived; confirm it in the authenticated Android Client.\n'
agent_args=(
  machine agent
  --id "$node_id"
  --name "$node_name"
  --control-url "$control_url"
  --state-dir "$state_dir"
)
if [[ "$mode" == relay ]]; then
  agent_args+=(--relay-only)
fi
"$binary_path" "${agent_args[@]}"
