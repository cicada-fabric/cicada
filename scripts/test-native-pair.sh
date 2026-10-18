#!/usr/bin/env bash
# Isolated real TCP/PQ/persistent-DB acceptance. No model or deployment actions.
set -euo pipefail
umask 077
mode=protocol
if [[ $# == 1 && "$1" == --store-regressions ]]; then mode=store
elif [[ $# == 1 && "$1" == --a3-core ]]; then mode=a3
elif [[ $# == 1 && "$1" == --a3-http ]]; then mode=a3-http
elif [[ $# == 1 && "$1" == --a3-size-store ]]; then mode=a3-size-store
elif [[ $# != 0 ]]; then printf 'Usage: scripts/test-native-pair.sh [--store-regressions|--a3-core|--a3-http|--a3-size-store]\n' >&2; exit 2; fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="$repo_root"
alternate_source="${CICADA_NATIVE_PAIR_SOURCE_ROOT:-${CICADA_NATIVE_PAIR_STORE_SOURCE_ROOT:-}}"
if [[ -n "$alternate_source" ]]; then
 if [[ "$mode" == protocol ]]; then printf 'Alternate source is limited to isolated core regressions.\n' >&2; exit 2; fi
 source_root="$(cd "$alternate_source" && pwd -P)"
 if [[ ! -f "$source_root/cicada-go/go.mod" ]]; then printf 'Store source must be a Cicada worktree.\n' >&2; exit 2; fi
fi
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="$workspace_root/.local"
module_cache="$local_root/cache/n2-acceptance/gomod-go1.27.2-stable"
build_cache="$local_root/cache/native-pair-acceptance/go-build"
image='sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61'
if [[ "$(id -u)" != 1000 || ! -d "$module_cache" ]] || ! docker image inspect "$image" >/dev/null 2>&1; then
 printf 'Requires UID1000, pinned offline Go image and populated read-only module cache.\n' >&2; exit 2
fi
mkdir -p "$local_root/state/native-pair-acceptance" "$local_root/evidence/native-pair-acceptance" "$local_root/artifacts/native-pair-acceptance" "$build_cache"
exec 9>"$build_cache/driver.lock"
flock -n 9 || { printf 'Task build cache already in use.\n' >&2; exit 2; }
state="$(mktemp -d "$local_root/state/native-pair-acceptance/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
run_id="$(basename "$state")"
evidence="$local_root/evidence/native-pair-acceptance/$run_id"
artifacts="$local_root/artifacts/native-pair-acceptance/$run_id"
mkdir "$evidence" "$artifacts" "$state/tmp"
container="cicada-native-pair-${run_id,,}"
cleanup() {
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.native-pair.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 "$repo_root/scripts/native_pair_evidence.py" snapshot "$source_root" "$evidence/source-before.json" "$repo_root"
common=(docker run --rm --name "$container" --label "cicada.native-pair.run=$run_id"
 --network none --read-only --cap-drop ALL --security-opt no-new-privileges
 --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
 --tmpfs /tmp:rw,nosuid,nodev,size=1g
 -e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
 -e GOCACHE=/gocache -e GOMODCACHE=/gomodcache -e TMPDIR=/state/tmp
 -e CICADA_N3_CICADA_BINARY=/out/cicada
 --mount "type=bind,src=$source_root,dst=/repo,readonly"
 --mount "type=bind,src=$repo_root,dst=/qa,readonly"
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
 --mount "type=bind,src=$build_cache,dst=/gocache"
 --mount "type=bind,src=$state,dst=/state"
 --mount "type=bind,src=$artifacts,dst=/out"
 --workdir /repo/cicada-go "$image")
lane() {
 local name="$1"; shift
 python3 -c 'import json,sys; open(sys.argv[1], "w").write(json.dumps(sys.argv[2:], indent=2) + "\n")' "$evidence/$name.command.json" "${common[@]}" "$@"
 set +e
 "${common[@]}" "$@" >"$evidence/$name.log" 2>&1
 local code="$?"
 set -e
 printf '%s\n' "$code" >"$evidence/$name.exit"
 printf 'Native pair %s exit=%s\n' "$name" "$code"
}
lane version go version
if [[ "$mode" != protocol ]]; then
 if [[ "$mode" == store ]]; then
  overlay=/qa/scripts/fixtures/native-pair/overlay.json
  package=./internal/store
  binary=nativepair-cache
  test_timeout=180s
  selector='^TestQANativePair(ReadCacheKeepsHistoryAcrossRateWindows|FutureStatusCannotSettleOrChangeRate|JoinDeadlineIsIndependentOfLiveLeaseExpiry)$'
 elif [[ "$mode" == a3 ]]; then
  overlay=/qa/scripts/fixtures/native-pair/overlay-a3.json
  package=./internal/server
  binary=nativepair-a3
  test_timeout=300s
  selector='^TestQANativePairA3(FirstConsentZeroSecondUsesOriginalGrants|SecondGrantFailureRollsBackBothMemberships|LostActivationAckRecoversAcceptedHistory|CurrentRequiredAndExactCoordinates)$'
 elif [[ "$mode" == a3-http ]]; then
  overlay=/qa/scripts/fixtures/native-pair/overlay-a3-http.json
  package=./internal/server
  binary=nativepair-a3-http
  test_timeout=180s
  selector='^TestQANativePairA3HTTPExactBodyAndAtomicRejection$'
 else
  overlay=/qa/scripts/fixtures/native-pair/overlay-a3-size-store.json
  package=./internal/store
  binary=nativepair-a3-size
  test_timeout=180s
  selector='^TestQANativePairA3DeliveryOverflowCannotPublishAuthority$'
 fi
 lane compile-tests go test -mod=readonly -overlay "$overlay" -c -o "/out/$binary.test" "$package"
 lane compile-race go test -mod=readonly -race -overlay "$overlay" -c -o "/out/$binary-race.test" "$package"
 if [[ "$(cat "$evidence/compile-tests.exit")" == 0 && "$(cat "$evidence/compile-race.exit")" == 0 ]]; then
  python3 "$repo_root/scripts/native_pair_evidence.py" binaries "$artifacts" "$evidence/binaries-before.json"
  lane harness go tool test2json -t "/out/$binary.test" -test.v -test.count=1 "-test.timeout=$test_timeout" "-test.run=$selector"
  lane race go tool test2json -t "/out/$binary-race.test" -test.v -test.count=1 "-test.timeout=$test_timeout" "-test.run=$selector"
  python3 "$repo_root/scripts/native_pair_evidence.py" binaries "$artifacts" "$evidence/binaries-after.json"
 else
  printf 'Required compilation failed; Store regression NOT_RUN.\n' >"$evidence/harness.log"
  printf '125\n' >"$evidence/harness.exit"
  printf '125\n' >"$evidence/race.exit"
 fi
 lane vet go vet -mod=readonly -overlay "$overlay" "$package"
else
 lane compile-cli env CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/cicada ./cmd/cicada
 lane compile-tests go test -mod=readonly -c -o /out/n3.test ./acceptance/n3
 if [[ "$(cat "$evidence/compile-cli.exit")" == 0 && "$(cat "$evidence/compile-tests.exit")" == 0 ]]; then
  python3 "$repo_root/scripts/native_pair_evidence.py" binaries "$artifacts" "$evidence/binaries-before.json"
  lane harness go tool test2json -t /out/n3.test -test.v -test.count=1 -test.timeout=4m '-test.run=^TestN3NativePair(BootstrapAndExactReplay|WrongNodeScopeIsFenced|PrepareLossBeforeForward|CompleteLossAfterCommit|MissingOwnerProofCannotBootstrap)$'
  python3 "$repo_root/scripts/native_pair_evidence.py" binaries "$artifacts" "$evidence/binaries-after.json"
 else
  printf 'Required compilation failed; runtime NOT_RUN.\n' >"$evidence/harness.log"
  printf '125\n' >"$evidence/harness.exit"
 fi
 lane vet go vet -mod=readonly ./acceptance/n3
fi
python3 "$repo_root/scripts/native_pair_evidence.py" snapshot "$source_root" "$evidence/source-after.json" "$repo_root"
cleanup
owned=false
if docker inspect "$container" >/dev/null 2>&1; then owned=true; fi
python3 "$repo_root/scripts/native_pair_evidence.py" finish "$evidence" "$artifacts" "$image" "$owned" "$mode"
