#!/usr/bin/env bash
# Independent N2 acceptance; baseline lanes do not claim activation acceptance.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
local_root="${CICADA_N2_LOCAL_ROOT:-$workspace_root/.local}"
module_cache="${CICADA_N2_GOMODCACHE:-$local_root/cache/gomod}"
build_cache="${CICADA_N2_GOCACHE:-$local_root/cache/n2-acceptance/go-build}"
image="${CICADA_N2_GO_IMAGE:-sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61}"
require_n2=false
if [[ "${1:-}" == --require-n2 ]]; then require_n2=true; shift; fi
if [[ "$#" -ne 0 ]]; then printf '%s\n' 'Usage: scripts/test-native-app-n2.sh [--require-n2]' >&2; exit 2; fi
if [[ ! "$image" =~ ^sha256:[0-9a-f]{64}$ || ! -d "$module_cache" ]]; then
 printf '%s\n' 'An immutable local Go image and populated offline module cache are required.' >&2; exit 2
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
 printf '%s\n' 'The pinned Go image must already be available locally.' >&2; exit 2
fi
fixture_args=()
synthetic_fixture="${CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR:-}"
if [[ -n "$synthetic_fixture" ]]; then
 [[ -d "$synthetic_fixture" && ! -L "$synthetic_fixture" ]] || { printf 'Synthetic fixture must be an existing directory, not a symlink.\n' >&2; exit 2; }
 synthetic_fixture="$(realpath -e "$synthetic_fixture")"
 [[ "$synthetic_fixture" == *synthetic* ]] || { printf 'Fixture path must visibly include synthetic.\n' >&2; exit 2; }
 for name in kem-private.pem signing-private.pem kem-public.pem signing-public.pem; do
  [[ -f "$synthetic_fixture/$name" && ! -L "$synthetic_fixture/$name" ]] || { printf 'Missing regular synthetic %s.\n' "$name" >&2; exit 2; }
 done
 [[ "$(find "$synthetic_fixture" -mindepth 1 -maxdepth 1 | wc -l)" -eq 4 ]] || { printf 'Synthetic fixture must contain only the four expected PEM files.\n' >&2; exit 2; }
 fixture_args=(--mount "type=bind,src=$synthetic_fixture,dst=/synthetic-keys,readonly" -e CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR=/synthetic-keys)
elif [[ "$require_n2" == true ]]; then
 printf 'Full N2 acceptance requires CICADA_APPKEYS_SYNTHETIC_OPENSSL_KEY_DIR with fresh synthetic four-PEM keys.\n' >&2; exit 2
fi
mkdir -p "$local_root/state/n2-acceptance" "$local_root/evidence/n2-acceptance" "$local_root/artifacts/n2-acceptance" "$build_cache"
exec 9>"$build_cache/driver.lock"
if ! flock -n 9; then printf '%s\n' 'This task build cache is in use; choose a distinct CICADA_N2_GOCACHE.' >&2; exit 2; fi
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
 "${fixture_args[@]}"
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
 run_lane account-process go tool test2json -t /out/n2.test -test.v -test.run '^TestN2Account(ProcessRecovery|PinAndExpiryBeforeSecrets|ConcurrentClaimAndConflictingReplay|ForeignScopeAndMissingDeviceProof|UnknownDeviceCannotUsePassword)$' -test.timeout=180s
 if [[ "$require_n2" == true ]]; then
  run_lane n2-process go tool test2json -t /out/n2.test -test.v -test.run '^TestN2(Activation|AccountReconcile)' -test.timeout=300s
 fi
else
 printf 'NOT_RUN: compile failed\n' >"$evidence/account-process.log"
 printf '125\n' >"$evidence/account-process.exit"
fi
run_lane existing-guards go test -json -mod=readonly -p=1 -count=1 -timeout=120s \
 ./internal/appcore ./internal/hubaccountwire ./internal/hubowner ./internal/e2ee ./internal/server \
 -run '^Test(ControllerRealHTTPAccountFlowAndExactUncertainRecovery|ActivationAndConnectionCardBoundaries|HubOwnerWithoutControlProvesKeysAndPreservesPermanentHistory|OwnerDeviceGrantVerifiesExactTrustedEnrollment|OwnerDeviceGrantRejectsTamperingNoncanonicalAndInvalidTime|HubAccountPQHTTPFlowSurvivesRestartAndRecoversRevokedLogout|OwnerAccountClaimCodeRoundTripAndStrictFraming|ActivationManifestMatchesWire|ActivationProofAndExactPacketRoundTrip|ActivationCodeAndLegacyExactIdentity|ActivationRejectsBindingNonceGrantAndLeaseSubstitution|ActivationChallengeCannotSettleAnotherExactPacket|AccountReconcileAndStatusBindExactTarget)$'
run_lane vet go vet -mod=readonly ./acceptance/n2
if [[ "$require_n2" == true ]]; then
 run_lane n2-guards go test -json -mod=readonly -p=1 -count=1 -timeout=180s ./internal/server ./internal/store -run '^TestN2'
 run_lane n2-race go test -json -race -mod=readonly -p=1 -count=1 -timeout=180s ./acceptance/n2 -run '^TestN2(ActivationConcurrentDistinctClaimsAndExactCompletion|AccountReconcileFencesLateCorrectRequestAcrossRestart)$'
fi
python3 "$repo_root/scripts/native_app_n2_evidence.py" snapshot "$repo_root" "$evidence/source-after.json"
cleanup
python3 "$repo_root/scripts/native_app_n2_evidence.py" containers "$evidence/containers-after.json" "$evidence/containers-before.json"
owned_present=false
if docker inspect "$container" >/dev/null 2>&1; then owned_present=true; fi
python3 "$repo_root/scripts/native_app_n2_evidence.py" finish "$evidence" "$artifacts" "$image" "$require_n2" "$owned_present"
