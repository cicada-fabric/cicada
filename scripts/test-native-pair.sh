#!/usr/bin/env bash
# Isolated real TCP/PQ/persistent-DB acceptance. No model or deployment actions.
set -euo pipefail
umask 077
mode=protocol
owner_groups_m7_only=0
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
elif [[ $# == 1 && "$1" == --codex-product-three-stage ]]; then mode=codex-product-three-stage
elif [[ $# == 1 && "$1" == --codex-product-other-uid ]]; then mode=codex-product-other-uid
elif [[ $# == 1 && "$1" == --codex-product-domain-app ]]; then mode=codex-product-domain-app
elif [[ $# == 1 && "$1" == --codex-product-domain-native ]]; then mode=codex-product-domain-native
elif [[ $# == 1 && "$1" == --codex-product-peer-form ]]; then mode=codex-product-peer-form
elif [[ $# == 1 && "$1" == --codex-product-peer-form-native ]]; then mode=codex-product-peer-form-native
elif [[ $# == 1 && "$1" == --peer-form-network ]]; then mode=peer-form-network
elif [[ $# == 1 && "$1" == --peer-form-network-focus ]]; then mode=peer-form-network-focus
elif [[ $# == 1 && "$1" == --direct-ip-tls ]]; then mode=direct-ip-tls
elif [[ $# == 1 && "$1" == --node-pair-trust ]]; then mode=node-pair-trust
elif [[ $# == 1 && "$1" == --owner-endpoint-groups ]]; then mode=owner-endpoint-groups
elif [[ $# == 1 && "$1" == --owner-endpoint-groups-m7 ]]; then mode=owner-endpoint-groups; owner_groups_m7_only=1
elif [[ $# != 0 ]]; then printf 'Usage: scripts/test-native-pair.sh [--store-regressions|--a3-core|--a3-http|--a3-size-store|--app-owner|--endpoint-security|--endpoint-security-boundaries|--endpoint-security-app-fixture|--endpoint-security-owner-directory|--endpoint-security-owner-directory-recovery|--codex-product-guards|--codex-product-cli|--codex-product-cold|--codex-product-three-stage|--codex-product-other-uid|--codex-product-domain-app|--codex-product-domain-native|--codex-product-peer-form|--codex-product-peer-form-native|--peer-form-network|--peer-form-network-focus|--direct-ip-tls|--node-pair-trust|--owner-endpoint-groups|--owner-endpoint-groups-m7]\n' >&2; exit 2; fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="$repo_root"
case "$mode" in
 codex-product-cli|codex-product-cold|codex-product-three-stage|codex-product-domain-native|codex-product-peer-form|codex-product-peer-form-native|direct-ip-tls|node-pair-trust)
  # Historical native lanes submit literal Join and require that legacy hook.
  # The new default must never send that command to a model as registration.
  if ! python3 - "$source_root/.agents/plugins/cicada/hooks/hooks.json" <<'PY'
import json,pathlib,sys
hooks=json.loads(pathlib.Path(sys.argv[1]).read_text())['hooks']
raise SystemExit(0 if 'UserPromptSubmit' in hooks else 1)
PY
  then
   printf 'LEGACY_LITERAL_NOT_RUN: this lane requires legacy UserPromptSubmit; default PreToolUse-only uses external CLI registration. Historical receipts and parser compatibility tests retain their source scope.\n' >&2
   exit 125
  fi
 ;;
esac
if [[ "$mode" == owner-endpoint-groups && ! -f "$source_root/cicada-go/acceptance/n3/owner_groups_runtime_test.go" ]]; then
 printf 'OWNER_GROUPS_NOT_RUN: formal App/Hub/Node/native adapter has not been delivered; M1-M8 NOT_RUN.\n' >&2
 exit 125
fi
if [[ "$mode" == endpoint-security* && ! -f "$source_root/docs/native-endpoint-directory-contract.md" ]]; then
 printf 'Endpoint security requires the frozen Endpoint directory contract.\n' >&2; exit 2
fi
if [[ "$mode" == codex-product-* && ! -f "$source_root/cicada-go/cmd/cicada/codex_hook.go" ]]; then
 printf 'Codex product guards require the integrated consumer checkpoint; NOT_RUN.\n' >&2; exit 2
fi
if [[ "$mode" == codex-product-peer-form* && ! -f "$source_root/cicada-go/cmd/cicada/mcp_peer_selection.go" ]]; then
 printf 'Peer form requires the formally integrated selection contract; NOT_RUN.\n' >&2; exit 125
fi
if [[ "$mode" == node-pair-trust && ! -f "$source_root/docs/node-pair-trust-contract.md" ]]; then
 printf 'Node pairing requires the formally delivered Node-only shared contract; NOT_RUN.\n' >&2; exit 2
fi
alternate_source="${CICADA_NATIVE_PAIR_SOURCE_ROOT:-${CICADA_NATIVE_PAIR_STORE_SOURCE_ROOT:-}}"
if [[ "$mode" == peer-form-network* && ! -f "$source_root/cicada-go/cmd/cicada/mcp_peer_selection_test.go" ]]; then
 printf 'Peer Network gate requires the formally integrated real Network fixture; NOT_RUN.\n' >&2; exit 125
fi
if [[ -n "$alternate_source" ]]; then
 if [[ "$mode" == protocol || "$mode" == app-owner || "$mode" == endpoint-security* || "$mode" == codex-product-* || "$mode" == peer-form-network* || "$mode" == direct-ip-tls || "$mode" == node-pair-trust || "$mode" == owner-endpoint-groups ]]; then printf 'Alternate source is limited to isolated core regressions.\n' >&2; exit 2; fi
 source_root="$(cd "$alternate_source" && pwd -P)"
 if [[ ! -f "$source_root/cicada-go/go.mod" ]]; then printf 'Store source must be a Cicada worktree.\n' >&2; exit 2; fi
fi
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="$workspace_root/.local"
module_cache="$local_root/cache/n2-acceptance/gomod-go1.27.2-stable"
build_cache="$local_root/cache/native-pair-acceptance/go-build-go1.27.3"
image='golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110'
three_stage_parameters=()
if [[ "$mode" == codex-product-three-stage ]]; then
 export CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK="${CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK:-0077}"
 export CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS="${CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS:-1}"
 export CICADA_NATIVE_PAIR_CODEX_PREPARATION="${CICADA_NATIVE_PAIR_CODEX_PREPARATION:-none}"
 case "$CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK" in 0002|0077) ;; *) printf 'Daemon umask must be 0002 or 0077.\n' >&2; exit 2;; esac
 case "$CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS" in 1|2) ;; *) printf 'Fresh native Thread count must be 1 or 2.\n' >&2; exit 2;; esac
 if [[ "$CICADA_NATIVE_PAIR_CODEX_PREPARATION" != none ]]; then
  printf 'NOT_RUN: preparation policy is not frozen; only none is executable.\n' >&2; exit 125
 fi
 three_stage_parameters=(-e "CICADA_N3_CODEX_DAEMON_UMASK=$CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK"
  -e "CICADA_N3_CODEX_FRESH_THREADS=$CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS"
  -e "CICADA_N3_CODEX_PREPARATION=$CICADA_NATIVE_PAIR_CODEX_PREPARATION")
elif [[ -n "${CICADA_NATIVE_PAIR_CODEX_DAEMON_UMASK:-}${CICADA_NATIVE_PAIR_CODEX_FRESH_THREADS:-}${CICADA_NATIVE_PAIR_CODEX_PREPARATION:-}" ]]; then
 printf 'Daemon/preparation parameters require --codex-product-three-stage.\n' >&2; exit 2
fi
domain_native_parameters=()
if [[ "$mode" == codex-product-domain-native ]]; then
 export CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY="${CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY:-0}"
 case "$CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY" in 0|1) ;; *) printf 'Native domain login expiry parameter must be 0 or 1.\n' >&2; exit 2;; esac
 domain_native_parameters=(-e "CICADA_N3_DOMAIN_WAIT_LOGIN_EXPIRY=$CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY"
  -e CICADA_N3_DOMAIN_PUBLIC_SUMMARY=/state/domain-native-public-summary.json)
elif [[ -n "${CICADA_NATIVE_PAIR_DOMAIN_WAIT_LOGIN_EXPIRY:-}" ]]; then
 printf 'Domain login-expiry parameter requires --codex-product-domain-native.\n' >&2; exit 2
fi
codex_mount=()
if [[ "$mode" == codex-product-cli || "$mode" == codex-product-cold || "$mode" == codex-product-three-stage || "$mode" == codex-product-domain-native || "$mode" == codex-product-peer-form* || "$mode" == direct-ip-tls || "$mode" == node-pair-trust || "$mode" == owner-endpoint-groups ]]; then
 if [[ ! -f "$source_root/.agents/plugins/cicada/hooks/hooks.json" || ! -f "$source_root/.agents/plugins/cicada/.mcp.json" || ! -f "$source_root/.agents/plugins/cicada/.codex-plugin/plugin.json" ]]; then
  printf 'Installed-plugin gate requires the integrated existing-plugin assets; NOT_RUN.\n' >&2; exit 2
 fi
 codex_binary='/home/zyf/.codex/packages/standalone/releases/0.163.0-x86_64-unknown-linux-musl/bin/codex'
 codex_expected_sha='399ff69c431c066e40de318fba45c2b07f45a76b19939d247ee4828fc70c4215'
 codex_expected_version=''
 if [[ "$mode" == direct-ip-tls || "$mode" == node-pair-trust || "$mode" == owner-endpoint-groups || "$mode" == codex-product-peer-form* ]]; then
  codex_binary='/home/zyf/.codex/packages/standalone/releases/0.164.0-x86_64-unknown-linux-musl/bin/codex'
  codex_expected_sha='b93f6811d3f653f0fb83be4050d857fb9abbb111dfa2ce160563327daff7f306'
  codex_expected_version='0.164.0'
  export CICADA_NATIVE_PAIR_DIRECT_CODEX_VERSION="$codex_expected_version"
 fi
 python3 - "$codex_binary" "$codex_expected_sha" "$codex_expected_version" <<'PY'
import hashlib, json, pathlib, subprocess, sys
path = pathlib.Path(sys.argv[1])
if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('Reviewed Codex binary unavailable or changed; NOT_RUN.')
if sys.argv[3]:
    metadata=json.loads((path.parent.parent/'codex-package.json').read_text())
    version=subprocess.run([str(path),'--version'],capture_output=True,text=True,check=True,timeout=10).stdout.strip()
    if metadata.get('version') != sys.argv[3] or version != 'codex-cli '+sys.argv[3]:
        raise SystemExit('Direct-IP Codex package/runtime version mismatch; NOT_RUN.')
PY
 export CICADA_NATIVE_PAIR_CODEX_BINARY="$codex_binary"
 codex_mount=(--mount "type=bind,src=$codex_binary,dst=/tools/codex,readonly" -e CICADA_N3_CODEX_BINARY=/tools/codex)
fi
license_mount=()
if [[ "$mode" == codex-product-three-stage || "$mode" == codex-product-domain-native || "$mode" == codex-product-peer-form* || "$mode" == direct-ip-tls || "$mode" == node-pair-trust || "$mode" == owner-endpoint-groups ]]; then
 licenses="${CICADA_NATIVE_PAIR_LICENSES_DIR:-}"
 if [[ -z "$licenses" || ! -f "$licenses/go/MODULES.json" || ! -f "$licenses/go/LICENSE" || ! -f "$licenses/cicada/LICENSE" ]]; then
  printf 'File-install gate requires matching complete CLI notices through CICADA_NATIVE_PAIR_LICENSES_DIR; NOT_RUN.\n' >&2; exit 2
 fi
 licenses="$(cd "$licenses" && pwd -P)"
 export CICADA_NATIVE_PAIR_LICENSES_DIR="$licenses"
 license_mount=(--mount "type=bind,src=$licenses,dst=/licenses,readonly")
fi
if [[ "$mode" == codex-product-three-stage || "$mode" == codex-product-domain-native || "$mode" == codex-product-peer-form* || "$mode" == direct-ip-tls || "$mode" == node-pair-trust || "$mode" == owner-endpoint-groups ]]; then
 codex_package="$(dirname "$(dirname "$codex_binary")")"
 if [[ ! -f "$codex_package/codex-package.json" || ! -f "$codex_package/bin/codex-code-mode-host" ]]; then
  printf 'Persistent daemon gate requires the existing complete reviewed Codex package; NOT_RUN.\n' >&2; exit 2
 fi
 export CICADA_NATIVE_PAIR_CODEX_PACKAGE="$codex_package"
 codex_mount+=(--mount "type=bind,src=$codex_package,dst=/tools/codex-package,readonly")
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
other_uid_worker_pid=''
other_uid_parameters=()
direct_ip_parameters=()
if [[ "$mode" == direct-ip-tls ]]; then
 direct_ip_parameters=(-e CICADA_N3_DIRECT_IP_TLS=1)
elif [[ "$mode" == node-pair-trust ]]; then
 direct_ip_parameters=(-e CICADA_N3_NODE_PAIR_TRUST=1
  -e CICADA_N3_NODE_PAIR_CONSUMER_PUBLIC_SUMMARY=/state/node-pair-native-consumer-public-summary.json)
elif [[ "$mode" == codex-product-peer-form* ]]; then
 direct_ip_parameters=(-e CICADA_N3_PEER_FORM=1 -e CICADA_N3_PEER_FORM_PUBLIC_SUMMARY=/state/peer-form-native-public-summary.json)
elif [[ "$mode" == owner-endpoint-groups ]]; then
 direct_ip_parameters=(-e CICADA_N3_OWNER_ENDPOINT_GROUPS=1)
fi
if [[ "$mode" == codex-product-other-uid ]]; then
 mkdir "$state/other-uid-control"
 other_uid_parameters=(-e CICADA_N3_OTHER_UID_CONTROL=/state/other-uid-control)
fi
cleanup() {
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.native-pair.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
 if [[ -n "$other_uid_worker_pid" ]]; then
  kill "$other_uid_worker_pid" >/dev/null 2>&1 || true
  wait "$other_uid_worker_pid" >/dev/null 2>&1 || true
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
 "${license_mount[@]}"
 "${three_stage_parameters[@]}"
 "${domain_native_parameters[@]}"
 "${other_uid_parameters[@]}"
 "${direct_ip_parameters[@]}"
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
other_uid_worker() {
 local deadline=$((SECONDS + 100))
 while [[ ! -f "$state/other-uid-control/request.json" && "$SECONDS" -lt "$deadline" ]]; do sleep .1; done
 if [[ ! -f "$state/other-uid-control/request.json" ]]; then
  printf 'NOT_RUN: actual Node fixture did not request the probe.\n' >&2; return 125
 fi
 bash "$repo_root/scripts/fixtures/native-pair/other_uid_host.sh" "$container" "$run_id" "$state/other-uid-control/request.json" "$state/other-uid-control/result.json"
}
if [[ "$mode" != protocol && "$mode" != app-owner && "$mode" != endpoint-security* && "$mode" != codex-product-* && "$mode" != direct-ip-tls && "$mode" != node-pair-trust && "$mode" != owner-endpoint-groups ]]; then
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
 elif [[ "$mode" == peer-form-network* ]]; then
  overlay=/qa/scripts/fixtures/native-pair/overlay-peer-network.json
  package=./cmd/cicada
  binary=peer-network
  test_timeout=300s
  selector='^TestQAPeerForm(RealNetworkProcessRestartAndLostResponse|NetworkOnlyOriginalRecovery)$'
  if [[ "$mode" == peer-form-network-focus ]]; then
   selector='^TestQAPeerForm(RealNetworkProcessRestartAndLostResponse|NetworkOnlyOriginalRecovery)$/^(known-renewal|unsupported-.*)$'
  fi
  lane compile-cli env CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/cicada ./cmd/cicada
 else
  overlay=/qa/scripts/fixtures/native-pair/overlay-a3-size-store.json
  package=./internal/store
  binary=nativepair-a3-size
  test_timeout=180s
  selector='^TestQANativePairA3DeliveryOverflowCannotPublishAuthority$'
 fi
 lane compile-tests go test -mod=readonly -overlay "$overlay" -c -o "/out/$binary.test" "$package"
 if [[ "$mode" != peer-form-network-focus ]]; then
  lane compile-race go test -mod=readonly -race -overlay "$overlay" -c -o "/out/$binary-race.test" "$package"
 fi
 if [[ "$(cat "$evidence/compile-tests.exit")" == 0 ]] && { [[ "$mode" == peer-form-network-focus ]] || [[ "$(cat "$evidence/compile-race.exit")" == 0 ]]; } && { [[ "$mode" != peer-form-network* ]] || [[ "$(cat "$evidence/compile-cli.exit")" == 0 ]]; }; then
  python3 "$repo_root/scripts/native_pair_evidence.py" binaries "$artifacts" "$evidence/binaries-before.json"
  lane harness go tool test2json -t "/out/$binary.test" -test.v -test.count=1 "-test.timeout=$test_timeout" "-test.run=$selector"
  if [[ "$mode" != peer-form-network-focus ]]; then
   lane race go tool test2json -t "/out/$binary-race.test" -test.v -test.count=1 "-test.timeout=$test_timeout" "-test.run=$selector"
  fi
  if [[ "$mode" == peer-form-network ]]; then
   shared_selector='^TestNetwork(PairSharedRenewalCannotRotateOriginalHeartbeat|LocalDomainSharedRenewalCannotRotateOriginalHeartbeat|IndependentRenewalDoesNotAcquireNewGrants)$'
   lane shared-access go test -mod=readonly -json -count=1 -timeout=120s -run "$shared_selector" ./internal/store
   lane shared-access-race go test -mod=readonly -race -json -count=1 -timeout=120s -run "$shared_selector" ./internal/store
   lane network-history go test -mod=readonly -json -count=1 -timeout=60s -run '^TestNativeContextExistingNetworkEndpointLookupIsExactAndReadOnly$' ./internal/nodeinbox
   lane network-history-race go test -mod=readonly -race -json -count=1 -timeout=60s -run '^TestNativeContextExistingNetworkEndpointLookupIsExactAndReadOnly$' ./internal/nodeinbox
  fi
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
  elif [[ "$mode" == codex-product-three-stage ]]; then
   selector='^TestN3CodexProductThreeStagePersistentDaemon$'
   runtime_timeout=7m
  elif [[ "$mode" == codex-product-other-uid ]]; then
   selector='^TestN3CodexProductOtherUIDPrivateBoundary$'
  elif [[ "$mode" == codex-product-domain-app ]]; then
   selector='^TestN3LocalDomainActualAppOwnerPolicy$'
  elif [[ "$mode" == codex-product-domain-native ]]; then
   selector='^TestN3LocalDomainNativeOriginalDaemonAB$'
   runtime_timeout=30m
  elif [[ "$mode" == codex-product-peer-form ]]; then
   selector='^TestN3PeerForm(UnverifiedContext|NativeOriginalDaemonAB)$'
   runtime_timeout=12m
  elif [[ "$mode" == codex-product-peer-form-native ]]; then
   selector='^TestN3PeerFormNativeOriginalDaemonAB$'
   runtime_timeout=12m
  elif [[ "$mode" == direct-ip-tls ]]; then
   selector='^TestN3DirectIPTLSAcceptance$'
   runtime_timeout=20m
  elif [[ "$mode" == owner-endpoint-groups ]]; then
   selector='^TestN3OwnerEndpointGroupsAcceptance$'
   runtime_timeout=90m
   if [[ "$owner_groups_m7_only" == 1 ]]; then selector='^TestN3OwnerEndpointGroupsM7Only$'; fi
  elif [[ "$mode" == node-pair-trust ]]; then
   selector='^TestN3NodePairTrustAcceptance$'
   runtime_timeout=20m
  else
   selector='^TestN3NativePair(BootstrapAndExactReplay|WrongNodeScopeIsFenced|PrepareLossBeforeForward|CompleteLossAfterCommit|MissingOwnerProofCannotBootstrap)$'
  fi
  if [[ "$mode" == codex-product-other-uid ]]; then
   other_uid_worker >"$evidence/other-uid-host.log" 2>&1 &
   other_uid_worker_pid=$!
  fi
  if [[ "$mode" == direct-ip-tls ]]; then
   lane direct-ip-fixture go tool test2json -t /out/n3.test -test.v -test.count=1 -test.timeout=45s '-test.run=^TestN3DirectIPTLS(FaultFixture|SharedFaults|CipherFaultFixture)$'
  elif [[ "$mode" == node-pair-trust ]]; then
   lane node-pair-fixture go tool test2json -t /out/n3.test -test.v -test.count=1 -test.timeout=45s '-test.run=^TestN3NodePairTrust(DiscoveryBoundary|OpaqueFaultBoundary)$'
  fi
  lane harness go tool test2json -t /out/n3.test -test.v -test.count=1 "-test.timeout=$runtime_timeout" "-test.run=$selector"
  if [[ "$mode" == codex-product-domain-native && -f "$state/domain-native-public-summary.json" ]]; then
   cp "$state/domain-native-public-summary.json" "$evidence/domain-native-public-summary.json"
  fi
  if [[ "$mode" == direct-ip-tls && -f "$state/direct-ip-native-public-summary.json" ]]; then
   cp "$state/direct-ip-native-public-summary.json" "$evidence/direct-ip-native-public-summary.json"
  fi
  if [[ "$mode" == node-pair-trust && -f "$state/node-pair-native-consumer-public-summary.json" ]]; then
   cp "$state/node-pair-native-consumer-public-summary.json" "$evidence/node-pair-native-consumer-public-summary.json"
  fi
  if [[ "$mode" == codex-product-peer-form* && -f "$state/peer-form-native-public-summary.json" ]]; then
   cp "$state/peer-form-native-public-summary.json" "$evidence/peer-form-native-public-summary.json"
  fi
  if [[ "$mode" == codex-product-other-uid ]]; then
   set +e
   wait "$other_uid_worker_pid"
   printf '%s\n' "$?" >"$evidence/other-uid-host.exit"
   set -e
   other_uid_worker_pid=''
   if [[ -f "$state/other-uid-control/result.json" ]]; then cp "$state/other-uid-control/result.json" "$evidence/other-uid-observation.json"; fi
  fi
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
if [[ "$mode" == owner-endpoint-groups ]] && ! docker info >/dev/null 2>&1; then owned=UNKNOWN; fi
evidence_mode="$mode"
if [[ "$owner_groups_m7_only" == 1 ]]; then evidence_mode=owner-endpoint-groups-m7; fi
python3 "$repo_root/scripts/native_pair_evidence.py" finish "$evidence" "$artifacts" "$image" "$owned" "$evidence_mode"
