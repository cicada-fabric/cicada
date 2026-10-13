#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install-cicada-server.sh [--help]

Build and run the minimal loopback-only Hub for an existing deployment's
explicit backed-up update. This helper does not provision a new Hub and refuses
pristine state before creating a container or volume. For first setup, follow
the manual Hub setup and deployment procedure in docs/hub-owner-bootstrap.md.
This command does not download a release artifact, ask for a provider key, or
replace another Compose project unless CICADA_DEPLOY_PROJECT names it.

Environment:
  CICADA_API_PORT       Loopback listen port (default 8788)
  CICADA_HUB_IMAGE      Local image tag (default cicada-hub:local)
  CICADA_HUB_VOLUME     Hub volume (default cicada-v2-local-hub-state, or <project>-hub-state)
  CICADA_DEPLOY_UPDATE  Set to 1 for an existing project; a fresh backup is required
  CICADA_DEPLOY_PROJECT Validated project name (default cicada-v2-local)
  CICADA_HUB_UPDATE_BACKUP  New private external directory for a verified
                            Hub backup before an existing-project update
EOF
}

die() {
  printf 'cicada Hub installer: %s\n' "$*" >&2
  exit 1
}

cleanup_update_scratch() {
  if [[ -n "${update_scratch:-}" && -d "$update_scratch" && ! -L "$update_scratch" ]]; then
    rm -rf -- "$update_scratch"
  fi
}

backup_check() {
  python3 "$repo_root/scripts/hub-update-backup-check.py" "$@"
}

compose_config_matches_update() {
  local config_path="$1"
  backup_check compose "$config_path" "$project" "$CICADA_HUB_VOLUME" "$CICADA_HUB_IMAGE" "$CICADA_API_PORT"
}

read_existing_hub() {
  local inspect_path="$1" cid="$2" output_path="$3"
  backup_check container "$inspect_path" "$cid" "$project" "$CICADA_HUB_VOLUME" "$output_path"
}

read_volume_mountpoint() {
  local inspect_path="$1" output_path="$2"
  backup_check volume "$inspect_path" "$project" "$CICADA_HUB_VOLUME" "$output_path"
}

validate_external_backup_destination() {
  local destination="$1" mountpoint="$2" uid="$3" gid="$4"
  backup_check destination "$destination" "$mountpoint" "$repo_root" "$uid" "$gid"
}

check_running_volume_consumers() {
  local hub_cid="$1" allow_hub="$2" ids id inspect_path
  # Inspect only Docker's exact named-volume candidates, not every container.
  # This cannot census host processes or arbitrary bind-mounted writers. The
  # operator must quiesce every writer; the backup command's StateDir
  # maintenance lease and SQLite snapshot lock remain the authoritative guard.
  ids="$(docker ps -q --no-trunc --filter "volume=$CICADA_HUB_VOLUME")" || return 1
  while IFS= read -r id; do
    [[ -n "$id" ]] || continue
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] || return 1
    if [[ "$id" == "$hub_cid" && "$allow_hub" == 1 ]]; then
      continue
    fi
    inspect_path="$update_scratch/consumer-$id.json"
    docker inspect "$id" >"$inspect_path" 2>/dev/null || return 1
    if backup_check consumer "$inspect_path" "$CICADA_HUB_VOLUME"; then
      :
    else
      return 1
    fi
  done <<<"$ids"
  return 0
}

compare_backup_manifests() {
  local backup_json="$1" verify_json="$2" archive_manifest="$3"
  backup_check manifests "$backup_json" "$verify_json" "$archive_manifest"
}

update_existing_hub() {
  local existing="$1" backup_destination="$2" cid count image_id initial_status volume_source volume_mountpoint
  local container_json volume_json image_json compose_json uid_probe uid_gid state_owner uid gid
  local backup_parent backup_name backup_inside image_role sha256
  local project_volumes update_run_id
  local -a update_helper_labels=()
  [[ -n "$backup_destination" ]] || die "an existing-project update requires CICADA_HUB_UPDATE_BACKUP to name a new private external backup directory"
  command -v python3 >/dev/null 2>&1 || die "Python 3 is required to validate a Hub update backup"
  mapfile -t existing_ids <<<"$existing"
  count="${#existing_ids[@]}"
  [[ "$count" -eq 1 && "${existing_ids[0]}" =~ ^[0-9a-f]{64}$ ]] || die "update requires exactly one inspectable container in the Compose project"
  cid="${existing_ids[0]}"

  umask 077
  update_scratch="$(mktemp -d "${TMPDIR:-/tmp}/cicada-hub-update.XXXXXXXX")" || die "could not create private update-preflight scratch"
  chmod 0700 "$update_scratch" || die "could not protect update-preflight scratch"
  trap cleanup_update_scratch EXIT
  update_run_id="update-${BASHPID}-${RANDOM}"
  update_helper_labels=(--label org.cicada.update-helper=1 --label "org.cicada.update-project=$project" --label "org.cicada.update-run=$update_run_id")
  printf 'Hub update helper ownership label: org.cicada.update-run=%s\n' "$update_run_id"

  compose_json="$update_scratch/compose.json"
  "${compose[@]}" config --format json >"$compose_json" 2>/dev/null || die "could not resolve Compose update configuration"
  compose_config_matches_update "$compose_json" || die "resolved Compose configuration does not match the single Hub volume scope"

  project_volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" || die "could not inspect Compose-owned volumes"
  mapfile -t project_volume_ids <<<"$project_volumes"
  [[ "${#project_volume_ids[@]}" -eq 1 && "${project_volume_ids[0]}" == "$CICADA_HUB_VOLUME" ]] || die "update requires exactly the configured Compose-owned Hub volume; preserve and resolve stale or ambiguous volumes"

  container_json="$update_scratch/container.json"
  docker inspect "$cid" >"$container_json" 2>/dev/null || die "could not inspect the existing Hub container"
  local -a container_fields=()
  read_existing_hub "$container_json" "$cid" "$update_scratch/container.fields" || die "existing project is not exactly one Hub container on the configured volume"
  mapfile -t container_fields <"$update_scratch/container.fields"
  image_id="${container_fields[0]:-}"
  initial_status="${container_fields[1]:-}"
  volume_source="${container_fields[2]:-}"
  [[ -n "$image_id" && -n "$initial_status" && -n "$volume_source" ]] || die "existing Hub inspection was incomplete"

  volume_json="$update_scratch/volume.json"
  docker volume inspect "$CICADA_HUB_VOLUME" >"$volume_json" 2>/dev/null || die "could not inspect the configured Hub volume"
  read_volume_mountpoint "$volume_json" "$update_scratch/volume.mountpoint" || die "configured Hub volume ownership labels are not exact"
  volume_mountpoint="$(<"$update_scratch/volume.mountpoint")"
  [[ "$volume_source" == "$volume_mountpoint" ]] || die "existing Hub container and Compose volume do not resolve to the same source"

  image_json="$update_scratch/image.json"
  docker image inspect "$image_id" >"$image_json" 2>/dev/null || die "could not inspect the currently deployed Hub image"
  image_role="$(backup_check image "$image_json" "$image_id")" || die "current image is not an identified CICADA Hub image"
  [[ "$image_role" == hub ]] || die "current image role is not Hub"

  backup_parent="$(dirname -- "$backup_destination")"
  backup_name="$(basename -- "$backup_destination")"
  [[ -n "$backup_name" && "$backup_name" != . && "$backup_name" != .. ]] || die "backup destination path is invalid"

  # Check both backup subcommands before stopping the existing service. A
  # legacy image without these exact CLI operations must not be updated by
  # guessing at another backup format.
  for subcommand in backup verify; do
    local probe_path="$update_scratch/probe-$subcommand.txt" expected
    if docker run --rm "${update_helper_labels[@]}" --network none --read-only --cap-drop ALL \
      --security-opt no-new-privileges:true --entrypoint /usr/local/bin/cicada \
      "$image_id" migration "$subcommand" >"$update_scratch/probe.stdout" 2>"$probe_path"; then
      die "current Hub image unexpectedly accepted an incomplete migration $subcommand command"
    fi
    if [[ "$subcommand" == backup ]]; then
      expected='migration backup requires explicit --state-dir and --output'
    else
      expected='migration verify requires explicit --backup'
    fi
    [[ "$(<"$probe_path")" == "$expected" ]] || die "current Hub image does not expose the supported migration $subcommand CLI"
  done

  uid_probe="$update_scratch/uid.txt"
  docker run --rm "${update_helper_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --mount "type=volume,src=$CICADA_HUB_VOLUME,dst=/state,readonly,volume-nocopy" \
    --entrypoint /bin/sh "$image_id" -c \
    'printf "%s:%s\n" "$(id -u)" "$(id -g)"; stat -c "%u:%g:%a" /state' \
    >"$uid_probe" 2>/dev/null || die "could not identify the Hub state owner without modifying the volume"
  mapfile -t uid_lines <"$uid_probe"
  [[ "${#uid_lines[@]}" -eq 2 && "${uid_lines[0]}" =~ ^[0-9]+:[0-9]+$ && "${uid_lines[1]}" =~ ^[0-9]+:[0-9]+:700$ ]] || die "Hub state owner or private directory mode is unknown"
  uid_gid="${uid_lines[0]}"
  state_owner="${uid_lines[1]}"
  uid="${uid_gid%%:*}"; gid="${uid_gid#*:}"
  [[ "$state_owner" == "$uid_gid:700" ]] || die "current Hub image user does not own the private StateDir"
  [[ "$uid" == "$(id -u)" && "$gid" == "$(id -g)" ]] || die "host user cannot safely retain and verify the Hub backup; UID/GID must match the Hub StateDir"
  validate_external_backup_destination "$backup_destination" "$volume_mountpoint" "$uid" "$gid" || die "backup destination must be a new canonical private directory outside the repository and Hub volume, owned by the Hub UID/GID"

  check_running_volume_consumers "$cid" 1 || die "another running read-write container uses the Hub volume"
  if [[ "$initial_status" == running ]]; then
    docker stop --time 30 "$cid" >/dev/null || die "could not stop the exact existing Hub before offline backup; no update was run"
  fi
  docker inspect "$cid" >"$update_scratch/container.stopped.json" 2>/dev/null || die "existing Hub container disappeared before backup; no update was run"
  read_existing_hub "$update_scratch/container.stopped.json" "$cid" "$update_scratch/container.stopped.fields" || die "existing Hub identity or volume changed while stopping; no update was run"
  mapfile -t stopped_fields <"$update_scratch/container.stopped.fields"
  if [[ "$initial_status" == running ]]; then
    [[ "${stopped_fields[1]:-}" == exited ]] || die "existing Hub stop did not reach the exited state"
  else
    [[ "${stopped_fields[1]:-}" == "$initial_status" ]] || die "existing Hub state changed before the offline backup"
  fi
  [[ "${stopped_fields[0]:-}" == "$image_id" && "${stopped_fields[2]:-}" == "$volume_source" ]] || die "existing Hub was not confirmed stopped with its original image and volume"
  printf 'Existing Hub state confirmed: %s (%s, image %s); backing up volume %s.\n' "${stopped_fields[1]}" "$cid" "$image_id" "$CICADA_HUB_VOLUME"
  check_running_volume_consumers "$cid" 0 || die "a running read-write container still uses the Hub volume; no update was run"

  backup_inside="/backup/$backup_name"
  if ! docker run --rm "${update_helper_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --user "$uid:$gid" \
    --mount "type=volume,src=$CICADA_HUB_VOLUME,dst=/state,volume-nocopy" \
    --mount "type=bind,src=$backup_parent,dst=/backup" \
    --entrypoint /usr/local/bin/cicada "$image_id" migration backup \
    --state-dir /state --output "$backup_inside" \
    >"$update_scratch/backup.json" 2>"$update_scratch/backup.stderr"; then
    die "verified Hub backup failed; the existing Hub remains stopped and no rebuild or migration was run"
  fi
  if ! docker run --rm "${update_helper_labels[@]}" --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges:true --user "$uid:$gid" \
    --mount "type=bind,src=$backup_parent,dst=/backup,readonly" \
    --entrypoint /usr/local/bin/cicada "$image_id" migration verify \
    --backup "$backup_inside" \
    >"$update_scratch/verify.json" 2>"$update_scratch/verify.stderr"; then
    die "Hub backup verification failed; the existing Hub remains stopped and no rebuild or migration was run"
  fi
  sha256="$(compare_backup_manifests "$update_scratch/backup.json" "$update_scratch/verify.json" "$backup_destination/manifest.json")" || die "backup and verify results do not match a complete supported Hub backup; no update was run"

  printf 'Verified current Hub backup: %s\n' "$backup_destination"
  printf 'Hub backup manifest SHA-256: %s\n' "$sha256"
  cleanup_update_scratch
  trap - EXIT
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
project="${CICADA_DEPLOY_PROJECT:-cicada-v2-local}"
[[ "$project" =~ ^[a-z0-9][a-z0-9_-]{0,62}$ ]] || die "CICADA_DEPLOY_PROJECT must be a lowercase Compose name"
if [[ -n "${CICADA_HUB_VOLUME:-}" ]]; then
  export CICADA_HUB_VOLUME
elif [[ "$project" == cicada-v2-local ]]; then
  export CICADA_HUB_VOLUME="cicada-v2-local-hub-state"
else
  export CICADA_HUB_VOLUME="${project}-hub-state"
fi
[[ "$CICADA_HUB_VOLUME" =~ ^[a-z0-9][a-z0-9_.-]{0,127}$ ]] || die "CICADA_HUB_VOLUME must be a valid lowercase volume name"
[[ "${CICADA_DEPLOY_UPDATE:-0}" == 0 || "${CICADA_DEPLOY_UPDATE:-0}" == 1 ]] || die "CICADA_DEPLOY_UPDATE must be 0 or 1"

compose=(docker compose --project-directory "$repo_root" -p "$project" -f "$repo_root/docker-compose.yml")
existing="$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$project")" || die "could not inspect the Compose project"
if [[ -n "$existing" && "${CICADA_DEPLOY_UPDATE:-0}" != 1 ]]; then
  die "project $project already has a container; preserve its state and set CICADA_DEPLOY_UPDATE=1 only for an intentional local update"
fi

"${compose[@]}" config -q || die "Compose configuration is invalid"
if [[ -n "$existing" ]]; then
  [[ "${CICADA_DEPLOY_UPDATE:-0}" == 1 ]] || die "existing project requires an explicit update"
  update_existing_hub "$existing" "${CICADA_HUB_UPDATE_BACKUP:-}"
elif [[ -n "${CICADA_HUB_UPDATE_BACKUP:-}" ]]; then
  die "CICADA_HUB_UPDATE_BACKUP is only valid when updating an existing project"
else
  project_volumes="$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" || die "could not determine whether project-owned volumes already exist"
  if [[ -n "$project_volumes" ]]; then
    die "Compose-owned volumes exist without a matching project container; preserve them and resolve the orphaned deployment before installing"
  fi
  volume_names="$(docker volume ls -q)" || die "could not determine whether the configured Hub volume already exists"
  while IFS= read -r volume_name; do
    if [[ "$volume_name" == "$CICADA_HUB_VOLUME" ]]; then
      die "the configured Hub volume exists without a matching project container; preserve it and resolve the orphaned deployment before installing"
    fi
  done <<<"$volume_names"
  die "pristine fresh Hub install is not supported by this Compose helper; follow docs/hub-owner-bootstrap.md for manual one-shot Hub setup and direct Docker serving"
fi
"${compose[@]}" up --detach --build --wait hub
printf 'CICADA Hub is healthy at http://127.0.0.1:%s\n' "$api_port"
printf 'Persistent Hub state volume: %s\n' "$CICADA_HUB_VOLUME"
printf 'This local Hub has no Codex, provider credential, or management bearer.\n'
printf 'A remote Node requires HTTPS and owner confirmation in the authenticated Android Client.\n'
printf 'Stop without deleting data: docker compose -p %s -f %s stop hub\n' "$project" "$repo_root/docker-compose.yml"
