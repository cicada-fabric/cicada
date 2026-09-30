#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install-cicada-server.sh [--help]

Build and start the minimal loopback-only Hub from this checkout.
This command does not download a release artifact, ask for a provider key, or
replace any project except the isolated Compose project cicada-v2-local.

Environment:
  CICADA_API_PORT       Loopback listen port (default 8788)
  CICADA_HUB_IMAGE      Local image tag (default cicada-hub:local)
  CICADA_HUB_VOLUME     Persistent Hub volume (default cicada-v2-local-hub-state)
  CICADA_DEPLOY_UPDATE  Set to 1 to rebuild/recreate this project if it exists
EOF
}

die() {
  printf 'cicada Hub installer: %s\n' "$*" >&2
  exit 1
}

if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  usage
  exit 0
fi
[[ $# -eq 0 ]] || die "unknown argument: $1"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ -f "$repo_root/docker/Dockerfile.hub" && -f "$repo_root/cicada-go/go.mod" ]] || die "run from a CICADA source checkout"
[[ "$(uname -s)" == Linux ]] || die "this local Compose profile uses Linux Docker host networking"
command -v docker >/dev/null 2>&1 || die "Docker Engine is required"
docker info >/dev/null 2>&1 || die "Docker Engine is not available to this user"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required"

api_port="${CICADA_API_PORT:-8788}"
[[ "$api_port" =~ ^[0-9]+$ ]] && ((api_port >= 1 && api_port <= 65535)) || die "CICADA_API_PORT must be 1..65535"
export CICADA_API_PORT="$api_port"
export CICADA_HUB_IMAGE="${CICADA_HUB_IMAGE:-cicada-hub:local}"
export CICADA_HUB_VOLUME="${CICADA_HUB_VOLUME:-cicada-v2-local-hub-state}"
project="cicada-v2-local"

compose=(docker compose --project-directory "$repo_root" -p "$project" -f "$repo_root/docker-compose.yml")
existing="$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
if [[ -n "$existing" && "${CICADA_DEPLOY_UPDATE:-0}" != 1 ]]; then
  die "project $project already has a container; preserve its state and set CICADA_DEPLOY_UPDATE=1 only for an intentional local update"
fi

"${compose[@]}" config -q || die "Compose configuration is invalid"
"${compose[@]}" up --detach --build --wait hub
printf 'CICADA Hub is healthy at http://127.0.0.1:%s\n' "$api_port"
printf 'Persistent Hub state volume: %s\n' "$CICADA_HUB_VOLUME"
printf 'This local Hub has no Codex, provider credential, or management bearer.\n'
printf 'A remote Node requires HTTPS and owner confirmation in the authenticated Android Client.\n'
printf 'Stop without deleting data: docker compose -p %s -f %s stop hub\n' "$project" "$repo_root/docker-compose.yml"
