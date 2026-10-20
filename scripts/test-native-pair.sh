#!/usr/bin/env bash
# Isolated real TCP/PQ/persistent-DB acceptance. No model or deployment actions.
set -euo pipefail
umask 077
mode=protocol
if [[ $# == 1 && "$1" == --store-regressions ]]; then mode=store
elif [[ $# == 1 && "$1" == --a3-core ]]; then mode=a3
elif [[ $# == 1 && "$1" == --a3-http ]]; then mode=a3-http
elif [[ $# == 1 && "$1" == --a3-size-store ]]; then mode=a3-size-store
elif [[ $# == 1 && "$1" == --app-owner ]]; then mode=app-owner
elif [[ $# == 1 && "$1" == --endpoint-security ]]; then mode=endpoint-security
elif [[ $# == 1 && "$1" == --endpoint-security-boundaries ]]; then mode=endpoint-security-boundaries
elif [[ $# == 1 && "$1" == --endpoint-security-app-fixture ]]; then mode=endpoint-security-app-fixture
elif [[ $# == 1 && "$1" == --endpoint-security-owner-directory ]]; then mode=endpoint-security-owner-directory
elif [[ $# == 1 && "$1" == --endpoint-security-owner-directory-recovery ]]; then mode=endpoint-security-owner-directory-recovery
elif [[ $# == 1 && "$1" == --codex-product-guards ]]; then mode=codex-product-guards
elif [[ $# == 1 && "$1" == --codex-product-cli ]]; then mode=codex-product-cli
elif [[ $# == 1 && "$1" == --codex-product-cold ]]; then mode=codex-product-cold
elif [[ $# != 0 ]]; then printf 'Usage: scripts/test-native-pair.sh [--store-regressions|--a3-core|--a3-http|--a3-size-store|--app-owner|--endpoint-security|--endpoint-security-boundaries|--endpoint-security-app-fixture|--endpoint-security-owner-directory|--endpoint-security-owner-directory-recovery|--codex-product-guards|--codex-product-cli|--codex-product-cold]\n' >&2; exit 2; fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="$repo_root"
if [[ "$mode" == endpoint-security* && ! -f "$source_root/docs/native-endpoint-directory-contract.md" ]]; then
 printf 'Endpoint security requires the frozen Endpoint directory contract.\n' >&2; exit 2
fi
if [[ "$mode" == codex-product-* && ! -f "$source_root/cicada-go/cmd/cicada/codex_hook.go" ]]; then
 printf 'Codex product guards require the integrated consumer checkpoint; NOT_RUN.\n' >&2; exit 2
fi
alternate_source="${CICADA_NATIVE_PAIR_SOURCE_ROOT:-${CICADA_NATIVE_PAIR_STORE_SOURCE_ROOT:-}}"
if [[ -n "$alternate_source" ]]; then
 if [[ "$mode" == protocol || "$mode" == app-owner || "$mode" == endpoint-security* || "$mode" == codex-product-* ]]; then printf 'Alternate source is limited to isolated core regressions.\n' >&2; exit 2; fi
 source_root="$(cd "$alternate_source" && pwd -P)"
 if [[ ! -f "$source_root/cicada-go/go.mod" ]]; then printf 'Store source must be a Cicada worktree.\n' >&2; exit 2; fi
fi
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="$workspace_root/.local"
module_cache="$local_root/cache/n2-acceptance/gomod-go1.27.2-stable"
build_cache="$local_root/cache/native-pair-acceptance/go-build-go1.27.3"
image='golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110'
codex_mount=()
if [[ "$mode" == codex-product-cli || "$mode" == codex-product-cold ]]; then
 if [[ ! -f "$source_root/.agents/plugins/cicada/hooks/hooks.json" || ! -f "$source_root/.agents/plugins/cicada/.mcp.json" || ! -f "$source_root/.agents/plugins/cicada/.codex-plugin/plugin.json" ]]; then
  printf 'Installed-plugin gate requires the integrated existing-plugin assets; NOT_RUN.\n' >&2; exit 2
 fi
 codex_binary='/home/zyf/.codex/packages/standalone/releases/0.163.0-x86_64-unknown-linux-musl/bin/codex'
 python3 - "$codex_binary" <<'PY'
import hashlib, pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != '399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215':
    raise SystemExit('Reviewed Codex 0.163.0 binary unavailable or changed; NOT_RUN.')
PY
 export CICADA_NATIVE_PAIR_CODEX_BINARY="$codex_binary"
 codex_mount=(--mount "type=bind,src=$codex_binary,dst=/tools/codex,readonly" -e CICADA_N3_CODEX_BINARY=/tools/codex)
fi
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
 "${codex_mount[@]}"
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
if [[ "$mode" != protocol && "$mode" != app-owner && "$mode" != endpoint-security* && "$mode" != codex-product-* ]]; then
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
  runtime_timeout=4m
  if [[ "$mode" == app-owner ]]; then
   selector='^TestN3AppPairActionsBootstrapDualConsentAndRevoke$'
  elif [[ "$mode" == endpoint-security ]]; then
   selector='^(TestN3HarnessMethodSpecificFaultBarrier|TestN3EndpointSecurity(ZeroAuthorityAndIdentityRetention|LeaveCASAndExactReplay|RegistrationFaultRecovery|ConcurrentOriginalRequest))$'
  elif [[ "$mode" == endpoint-security-boundaries ]]; then
   selector='^TestN3EndpointSecurity(ZeroAuthorityAndIdentityRetention|ConcurrentOriginalRequest)$'
  elif [[ "$mode" == endpoint-security-app-fixture ]]; then
   selector='^TestN3EndpointSecurityZeroAuthorityAndIdentityRetention$'
  elif [[ "$mode" == endpoint-security-owner-directory ]]; then
   selector='^TestN3OwnerDirectory(ActualAppReadsZeroRightsSnapshot|OldHubCannotStartRead|OriginalPendingRecovers)$'
  elif [[ "$mode" == endpoint-security-owner-directory-recovery ]]; then
   selector='^TestN3OwnerDirectoryOriginalPendingRecovers$'
  elif [[ "$mode" == codex-product-guards ]]; then
   selector='^TestN3CodexProduct(ContextRefusesMissingAndForged|MCPRestartRotatesConnectionNonce)$'
  elif [[ "$mode" == codex-product-cli ]]; then
   selector='^TestN3CodexProductInstalledPluginLiteralTUI$'
  elif [[ "$mode" == codex-product-cold ]]; then
   selector='^TestN3CodexProductColdLeaseBeforeFirstTool$'
   runtime_timeout=12m
  else
   selector='^TestN3NativePair(BootstrapAndExactReplay|WrongNodeScopeIsFenced|PrepareLossBeforeForward|CompleteLossAfterCommit|MissingOwnerProofCannotBootstrap)$'
  fi
  lane harness go tool test2json -t /out/n3.test -test.v -test.count=1 "-test.timeout=$runtime_timeout" "-test.run=$selector"
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
