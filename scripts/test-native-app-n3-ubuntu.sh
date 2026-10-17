#!/usr/bin/env bash
# Reuse the accepted Linux binaries in a separately attributed Ubuntu runtime.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="${CICADA_N3_LOCAL_ROOT:-$workspace_root/.local}"
if [[ "$#" -ne 1 || -z "${CICADA_N3_AGED_SEED:-}" || "$(id -u)" != 1000 ]]; then
 printf 'Usage: CICADA_N3_AGED_SEED=<stopped-expired-template> scripts/test-native-app-n3-ubuntu.sh <accepted-Linux-evidence-dir>\n' >&2; exit 2
fi
source_run="$(realpath "$1")"
source_artifacts="$local_root/artifacts/n3-acceptance/$(basename "$source_run")"
ubuntu='sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254'
builder='sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61'
docker image inspect "$ubuntu" >/dev/null 2>&1 || exit 2
docker image inspect "$builder" >/dev/null 2>&1 || exit 2
build_cache="$local_root/cache/n3-acceptance/go-build"
module_cache="${CICADA_N3_GOMODCACHE:-$local_root/cache/n2-acceptance/gomod-go1.27.2-stable}"
exec 9>"$build_cache/driver.lock"
flock -n 9 || exit 2
state="$(mktemp -d "$local_root/state/n3-acceptance/ubuntu-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
run_id="$(basename "$state")"
evidence="$local_root/evidence/n3-acceptance/$run_id"
mkdir "$evidence" "$state/tmp"
selector="$(python3 "$repo_root/scripts/native_app_n3_evidence.py" ubuntu-prepare "$source_run" "$source_artifacts" "$evidence/input.json")"
python3 "$repo_root/scripts/native_app_n3_evidence.py" copy-aged "$CICADA_N3_AGED_SEED" "$state/retained-aged-n2" \
 "$local_root/state/n3-acceptance" "$evidence/aged-seed-copy.json"
container="cicada-n3-${run_id,,}"
cleanup() {
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.n3.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
set +e
docker run --rm --name "$container" --label "cicada.n3.run=$run_id" --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)" \
 --tmpfs /tmp:rw,nosuid,nodev,size=1g -e TMPDIR=/state/tmp -e CICADA_N3_CICADA_BINARY=/out/cicada \
 -e CICADA_N3_RETAINED_FIXTURE=/state/retained-aged-n2 -e CICADA_N3_PRIVATE_DIAGNOSTICS=/state/private-diagnostics \
 --mount "type=bind,src=$source_artifacts,dst=/out,readonly" --mount "type=bind,src=$state,dst=/state" \
 "$ubuntu" /bin/sh -eu -c 'cat /etc/os-release >/state/container-os-release
uname -m >/state/container-machine
exec "$@"' qa-ubuntu /out/n3.test -test.v=test2json -test.count=1 -test.timeout=20m -test.run "$selector" \
 >"$evidence/raw.log" 2>&1
runtime_code="$?"
set -e
printf '%s\n' "$runtime_code" >"$evidence/runtime.exit"
cp "$state/container-os-release" "$state/container-machine" "$evidence/" 2>/dev/null || true
set +e
docker run --rm -i --name "$container" --label "cicada.n3.run=$run_id" --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --cpus=2 --memory=2g --pids-limit=128 --user "$(id -u):$(id -g)" \
 --tmpfs /tmp:rw,nosuid,nodev,size=512m -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache \
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly" --mount "type=bind,src=$build_cache,dst=/gocache" \
 "$builder" go tool test2json -t -p github.com/cicada-ai/cicada/acceptance/n3 \
 <"$evidence/raw.log" >"$evidence/harness.log" 2>&1
parse_code="$?"
set -e
printf '%s\n' "$parse_code" >"$evidence/parse.exit"
cleanup
owned=false
if docker inspect "$container" >/dev/null 2>&1; then owned=true; fi
python3 "$repo_root/scripts/native_app_n3_evidence.py" ubuntu-finish "$evidence" "$source_artifacts" "$ubuntu" "$owned"
