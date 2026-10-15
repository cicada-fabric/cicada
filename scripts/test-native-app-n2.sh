#!/usr/bin/env bash
# Independent N2 acceptance; baseline lanes do not claim activation acceptance.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="${CICADA_N2_LOCAL_ROOT:-$workspace_root/.local}"
module_cache="${CICADA_N2_GOMODCACHE:-$local_root/cache/gomod}"
build_cache="$local_root/cache/n2-acceptance/go-build"
image="${CICADA_N2_GO_IMAGE:-sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195}"
require_n2=false
if [[ "${1:-}" == --require-n2 ]]; then require_n2=true; shift; fi
if [[ "$#" -ne 0 ]]; then printf '%s\n' 'Usage: scripts/test-native-app-n2.sh [--require-n2]' >&2; exit 2; fi
if [[ ! "$image" =~ ^sha256:[0-9a-f]{64}$ || ! -d "$module_cache" ]]; then
 printf '%s\n' 'An immutable local Go image and populated offline module cache are required.' >&2; exit 2
fi
docker image inspect "$image" >/dev/null
mkdir -p "$local_root/state/n2-acceptance" "$local_root/evidence/n2-acceptance" "$local_root/artifacts/n2-acceptance" "$build_cache"
exec 9>"$build_cache/driver.lock"
if ! flock -n 9; then printf '%s\n' 'This task build cache is in use; use another CICADA_N2_LOCAL_ROOT.' >&2; exit 2; fi
run_state="$(mktemp -d "$local_root/state/n2-acceptance/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
run_id="$(basename "$run_state")"
evidence="$local_root/evidence/n2-acceptance/$run_id"
artifacts="$local_root/artifacts/n2-acceptance/$run_id"
mkdir "$evidence" "$artifacts" "$run_state/tmp"
container="cicada-n2-acceptance-${run_id,,}"
cleanup() {
 # Name and label are both required before removing this run's container.
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.n2.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$repo_root/scripts/native_app_n2_evidence.py" snapshot "$repo_root" "$evidence/source-before.json"
python3 "$repo_root/scripts/native_app_n2_evidence.py" containers "$evidence/containers-before.json"
common=(docker run --rm --name "$container" --label "cicada.n2.run=$run_id"
 --network none --read-only --cap-drop ALL --security-opt no-new-privileges
 --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
 --tmpfs /tmp:rw,nosuid,nodev,size=1g
 -e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
 -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache -e TMPDIR=/state/tmp
 --mount "type=bind,src=$repo_root,dst=/repo,readonly"
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
 --mount "type=bind,src=$build_cache,dst=/gocache"
 --mount "type=bind,src=$run_state,dst=/state"
 --mount "type=bind,src=$artifacts,dst=/out"
 --workdir /repo/cicada-go "$image")
run_lane() {
 local lane="$1"; shift
 set +e
 "${common[@]}" "$@" >"$evidence/$lane.log" 2>&1
 local status="$?"
 set -e
 printf '%s\n' "$status" >"$evidence/$lane.exit"
 printf 'N2 %s exit=%s\n' "$lane" "$status"
}
run_lane version go version
run_lane compile go test -mod=readonly -c -o /out/n2.test ./acceptance/n2
if [[ "$(cat "$evidence/compile.exit")" == 0 ]]; then
 run_lane account-process go tool test2json -t /out/n2.test -test.v -test.run '^TestN2Account' -test.timeout=180s
else
 printf 'NOT_RUN: compile failed\n' >"$evidence/account-process.log"
 printf '125\n' >"$evidence/account-process.exit"
fi
run_lane existing-guards go test -json -mod=readonly -p=1 -count=1 -timeout=120s \
 ./internal/appcore ./internal/hubaccountwire ./internal/hubowner ./internal/e2ee ./internal/server \
 -run '^Test(ControllerRealHTTPAccountFlowAndExactUncertainRecovery|ActivationAndConnectionCardBoundaries|HubOwnerWithoutControlProvesKeysAndPreservesPermanentHistory|OwnerDeviceGrantVerifiesExactTrustedEnrollment|OwnerDeviceGrantRejectsTamperingNoncanonicalAndInvalidTime|HubAccountPQHTTPFlowSurvivesRestartAndRecoversRevokedLogout|OwnerAccountClaimCodeRoundTripAndStrictFraming)$'
run_lane vet go vet -mod=readonly ./acceptance/n2
python3 "$repo_root/scripts/native_app_n2_evidence.py" snapshot "$repo_root" "$evidence/source-after.json"
cleanup
python3 "$repo_root/scripts/native_app_n2_evidence.py" containers "$evidence/containers-after.json" "$evidence/containers-before.json"
owned_present=false
if docker inspect "$container" >/dev/null 2>&1; then owned_present=true; fi
python3 "$repo_root/scripts/native_app_n2_evidence.py" finish "$evidence" "$artifacts" "$image" "$require_n2" "$owned_present"
