#!/usr/bin/env bash
# Independent actual-process acceptance; each selector has a distinct scope.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="${CICADA_N3_LOCAL_ROOT:-$workspace_root/.local}"
module_cache="${CICADA_N3_GOMODCACHE:-$local_root/cache/n2-acceptance/gomod-go1.27.2-stable}"
build_cache="${CICADA_N3_GOCACHE:-$local_root/cache/n3-acceptance/go-build-go1.27.3}"
image='golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110'
required=false
mode=preparation
case_name=''
for arg in "$@"; do
 case "$arg" in
  --require-n3) required=true ;;
  --runtime-core) mode=runtime ;;
  --auto-status-only) mode=auto ;;
  --app2-isolation-only) mode=app2-isolation ;;
  --case=*) mode=case; case_name="${arg#--case=}" ;;
  --discovery-only) mode=discovery ;;
  --seed-expiry) mode=seed ;;
  *) printf 'Usage: scripts/test-native-app-n3.sh [--require-n3 | --runtime-core | --auto-status-only | --app2-isolation-only | --case=TestName | --discovery-only | --seed-expiry]\n' >&2; exit 2 ;;
 esac
done
if [[ "$required" == true && "$mode" != preparation && "$mode" != runtime ]]; then
 printf 'A partial/setup result cannot satisfy --require-n3.\n' >&2; exit 2
fi
if [[ "$mode" == case ]]; then
 python3 "$repo_root/scripts/native_app_n3_evidence.py" case-selector "$case_name" >/dev/null || exit 2
fi
if [[ "$required" == true ]]; then
 mode=runtime
 if [[ -z "${CICADA_N3_AGED_SEED:-}" ]]; then printf 'Full N3 requires CICADA_N3_AGED_SEED from --seed-expiry after natural expiry.\n' >&2; exit 2; fi
fi
if [[ "$(id -u)" != 1000 || ! -d "$module_cache" ]] || ! docker image inspect "$image" >/dev/null 2>&1; then
 printf 'This fixture requires UID1000, the pinned offline Go image and read-only populated module cache.\n' >&2; exit 2
fi
mkdir -p "$local_root/state/n3-acceptance" "$local_root/evidence/n3-acceptance" "$local_root/artifacts/n3-acceptance" "$build_cache"
exec 9>"$build_cache/driver.lock"
flock -n 9 || { printf 'N3 task build cache is already in use.\n' >&2; exit 2; }
state="$(mktemp -d "$local_root/state/n3-acceptance/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
run_id="$(basename "$state")"
evidence="$local_root/evidence/n3-acceptance/$run_id"
artifacts="$local_root/artifacts/n3-acceptance/$run_id"
mkdir "$evidence" "$artifacts" "$state/tmp"
if [[ -n "${CICADA_N3_AGED_SEED:-}" ]]; then
 python3 "$repo_root/scripts/native_app_n3_evidence.py" copy-aged "$CICADA_N3_AGED_SEED" \
  "$state/retained-aged-n2" "$local_root/state/n3-acceptance" "$evidence/aged-seed-copy.json"
fi
container="cicada-n3-acceptance-${run_id,,}"
app2_supervisor=''
app2_environment=()
if [[ "$mode" == app2-isolation ]]; then
 mkdir "$state/app2" "$state/app2-control"
 app2_environment=(-e CICADA_N3_REQUIRE_APP2=1)
fi
cleanup() {
 if [[ -n "$app2_supervisor" ]]; then
  touch "$state/app2-control/stop"
  local supervisor_code=0
  wait "$app2_supervisor" || supervisor_code="$?"
  printf '%s\n' "$supervisor_code" >"$evidence/app2/supervisor.exit"
  app2_supervisor=''
 fi
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.n3.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$repo_root/scripts/native_app_n3_evidence.py" snapshot "$repo_root" "$evidence/source-before.json"
common=(docker run --rm --name "$container" --label "cicada.n3.run=$run_id"
 --network none --read-only --cap-drop ALL --security-opt no-new-privileges
 --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
 --tmpfs /tmp:rw,nosuid,nodev,size=1g
 -e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
 -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache -e TMPDIR=/state/tmp
 -e CICADA_N3_CICADA_BINARY=/out/cicada
 -e CICADA_N3_APP2_CONTROL=/state/app2-control
 "${app2_environment[@]}"
 -e CICADA_N3_PRIVATE_DIAGNOSTICS=/state/private-diagnostics
 -e CICADA_N3_RETAINED_FIXTURE=/state/retained-aged-n2
 -e "CICADA_N3_SEED_SOURCE_HEAD=$(git -C "$repo_root" rev-parse HEAD)"
 --mount "type=bind,src=$repo_root,dst=/repo,readonly"
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
 --mount "type=bind,src=$build_cache,dst=/gocache"
 --mount "type=bind,src=$state,dst=/state"
 --mount "type=bind,src=$artifacts,dst=/out"
 --workdir /repo/cicada-go "$image")
lane() {
 local name="$1"; shift
 python3 "$repo_root/scripts/native_app_n3_evidence.py" command "$evidence/$name.command.json" "${common[@]}" "$@"
 set +e
 "${common[@]}" "$@" >"$evidence/$name.log" 2>&1
 local code="$?"
 set -e
 printf '%s\n' "$code" >"$evidence/$name.exit"
 printf 'N3 %s exit=%s\n' "$name" "$code"
}
lane version go version
lane compile-cli env CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/cicada ./cmd/cicada
lane compile-tests go test -mod=readonly -c -o /out/n3.test ./acceptance/n3
if [[ "$(cat "$evidence/compile-cli.exit")" == 0 && "$(cat "$evidence/compile-tests.exit")" == 0 ]]; then
 python3 "$repo_root/scripts/native_app_n3_evidence.py" binaries "$artifacts" "$evidence/binaries-before.json"
 selector='^TestN3Harness(RealHubReplyRecovery|DelayedPacketCancellation|CommitBeforeReplyCrashWindow|ActualAppBootstrapAndResume|ActualAppVaultCommitBarrier)$'
 if [[ "$mode" == discovery ]]; then selector='^TestN3ActualAppUnsupportedCapabilitiesSendNoSecrets$'; fi
 if [[ "$mode" == seed ]]; then selector='^TestN3SeedRetainedN2Fixture$'; fi
 if [[ "$mode" == auto ]]; then selector="$(python3 "$repo_root/scripts/native_app_n3_evidence.py" auto-selector)"; fi
 if [[ "$mode" == app2-isolation ]]; then
  selector='^TestN3HarnessApp2ContainerIsolation$'
  python3 "$repo_root/scripts/native_app_n3_evidence.py" supervise-app2 "$state" "$artifacts" "$evidence/app2" "$image" "$container" "$run_id" &
  app2_supervisor="$!"
 fi
 timeout=120s
 if [[ "$mode" == runtime ]]; then
  selector="$(python3 "$repo_root/scripts/native_app_n3_evidence.py" runtime-selector "$required")"
  timeout=20m
 fi
 if [[ "$mode" == case ]]; then
  selector="$(python3 "$repo_root/scripts/native_app_n3_evidence.py" case-selector "$case_name")"
  timeout=20m
 fi
 lane harness go tool test2json -t /out/n3.test -test.v -test.count=1 "-test.timeout=$timeout" -test.run "$selector"
 python3 "$repo_root/scripts/native_app_n3_evidence.py" binaries "$artifacts" "$evidence/binaries-after.json"
else
 printf 'NOT_RUN: required compilation failed\n' >"$evidence/harness.log"
 printf '125\n' >"$evidence/harness.exit"
fi
lane vet go vet -mod=readonly ./acceptance/n3
python3 "$repo_root/scripts/native_app_n3_evidence.py" snapshot "$repo_root" "$evidence/source-after.json"
cleanup
owned=false
if docker inspect "$container" >/dev/null 2>&1; then owned=true; fi
python3 "$repo_root/scripts/native_app_n3_evidence.py" finish "$evidence" "$artifacts" "$image" "$required" "$owned" "$mode" "$case_name"
