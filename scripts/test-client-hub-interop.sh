#!/usr/bin/env bash
# Disposable real-TCP protocol test; never uses an existing Hub or model runtime.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
suite=client
if [[ "${1:-}" == "--suite" ]]; then
  [[ $# -eq 2 ]] || {
    printf 'Usage: %s [--suite client|network-m1]\n' "$0" >&2
    exit 2
  }
  suite="$2"
  shift 2
fi
[[ $# -eq 0 ]] || {
  printf 'Usage: %s [--suite client|network-m1]\n' "$0" >&2
  exit 2
}
case "$suite" in
  client)
    test_selector='^TestClientDockerHub(Smoke|RecoveryFixture)$'
    ;;
  network-m1)
    test_selector='^TestNetworkM1DockerHub$'
    ;;
  *)
    printf 'Unknown interop suite: %s\n' "$suite" >&2
    printf 'Usage: %s [--suite client|network-m1]\n' "$0" >&2
    exit 2
    ;;
esac
for command_name in python3 docker git; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'BLOCKED: required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
default_output_suite=client-interop
if [[ "$suite" == network-m1 ]]; then default_output_suite=network-m1-interop; fi
output_root="${CICADA_INTEROP_OUTPUT:-${repo_root}/.cicada-data/${default_output_suite}/$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "$output_root"
output_root="$(cd "$output_root" && pwd -P)"
mkdir "$output_root/.running" 2>/dev/null || {
  printf 'Interop output is already in use: %s\n' "$output_root" >&2
  exit 1
}
if [[ -e "$output_root/result.json" || -e "$output_root/test.log" ]]; then
  rmdir "$output_root/.running"
  printf 'Refusing to overwrite existing interop evidence: %s\n' "$output_root" >&2
  exit 1
fi
chmod 0700 "$output_root"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cicada-interop.XXXXXXXX")"
run_id="cicada-interop-$(basename "$scratch" | cut -d . -f 2)-$$"
run_id="${run_id,,}"
hub_container="${run_id}-hub"
test_container="${run_id}-test"
hub_image="${run_id}:hub"
test_image="${run_id}:test"
status=FAIL
phase=prerequisites
test_exit=-1
test_image_id=""
touch "$output_root/test.log"

finish() {
  local exit_code=$?
  trap - EXIT
  docker rm -f "$test_container" "$hub_container" >/dev/null 2>&1 || true
  docker image rm "$test_image" "$hub_image" >/dev/null 2>&1 || true
  if [[ "$status" != PASS && -s "$scratch/test.raw" ]]; then
    local diagnostic
    diagnostic="$(mktemp "${TMPDIR:-/tmp}/cicada-interop-failure.XXXXXXXX.log")"
    cp "$scratch/test.raw" "$diagnostic"
    printf 'Private failure diagnostics (not an upload artifact): %s\n' "$diagnostic" >&2
  fi
  python3 - "$output_root" "$scratch" "$status" "$phase" "$exit_code" "$test_exit" "$test_image_id" "$suite" <<'PY'
import datetime
import json
from pathlib import Path
import sys

output, scratch, status, phase, exit_code, test_exit, test_image_id, suite = sys.argv[1:]
build_file = Path(scratch) / "build.json"
if suite == "network-m1":
    schema_version = "cicada.network-m1-interop.v1"
    test_name = "TestNetworkM1DockerHub"
    level = "real_tcp_hub_network_m1"
    scope = ["same_hub_two_networks", "operator_mapping_activation",
             "same_session_multi_network_registration", "network_member_not_group_member",
             "filtered_discovery", "scoped_alias_ambiguity", "network_admin_grant_scope",
             "membership_revocation", "legacy_group_scope", "pending_group_quarantine",
             "encrypted_owner_topology_snapshot_multiple_networks",
             "owner_approved_network_direct_key_candidate_and_grant",
             "network_only_direct_sealed_send_claim_authorize_receipt",
             "network_only_direct_sealed_ask_reply_route_status",
             "control_free_http_network_direct_ask_reply_claim_authorize"]
else:
    schema_version = "cicada.client-hub-interop.v1"
    test_name = "TestClientDockerHubSmoke"
    level = "real_tcp_hub_go_protocol_client"
    scope = ["enrollment", "exact_enrollment_retry", "encrypted_snapshot",
             "exact_packet_retry", "completed_request_recovery",
             "still_processing_recovery", "uncertain_recovery_packet",
             "legacy_recovery_unavailable",
             "node_code_confirmation_and_heartbeat", "owner_status_topology_isolation"]
result = {
    "schema_version": schema_version,
    "suite": suite, "status": status, "phase": phase, "exit_code": int(exit_code),
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "level": level,
    "build": json.loads(build_file.read_text()) if build_file.exists() else None,
    "test_image_id": test_image_id,
    "test": {"name": test_name, "exit_code": int(test_exit)},
    "android": "NOT_RUN", "native_runtime": "NOT_RUN", "public_https": "NOT_RUN",
    "scope": scope,
}
if suite == "client":
    result["recovery_fault_test"] = {"name": "TestClientDockerHubRecoveryFixture", "exit_code": int(test_exit)}
(Path(output) / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(f"{status}: {output}/result.json")
PY
  rm -rf -- "$scratch"
  rmdir "$output_root/.running"
  exit "$exit_code"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! docker info >/dev/null 2>&1; then
  status=BLOCKED
  printf 'Docker daemon unavailable\n' >>"$output_root/test.log"
  exit 1
fi
phase=build
"${repo_root}/scripts/build-hub-image.sh" --image "$hub_image" \
  --interop-test-image "$test_image" --metadata-file "$scratch/build.json"
test_image_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["test_image"]["id"])' "$scratch/build.json")"
hub_image_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"]["id"])' "$scratch/build.json")"

phase=hub_start
mkdir "$scratch/state" "$scratch/workspaces"
printf 'disposable\n' >"$scratch/state/.cicada-disposable-recovery-fixture"
python3 - "$scratch" <<'PY'
from pathlib import Path
import secrets
import sys

root = Path(sys.argv[1])
token = secrets.token_hex(32)
(root / "hub.env").write_text("CICADA_API_TOKEN=" + token + "\n")
(root / "test.env").write_text("CICADA_TEST_HUB_TOKEN=" + token + "\n")
PY
docker run --rm -d --name "$hub_container" -p 127.0.0.1::8787 \
  --env-file "$scratch/hub.env" -v "$scratch/state:/state" \
  -v "$scratch/workspaces:/workspace" "$hub_image_id" >/dev/null
hub_port="$(docker port "$hub_container" 8787/tcp | cut -d : -f 2)"
hub_url="http://127.0.0.1:${hub_port}"

phase=provenance
python3 - "$hub_url" "$scratch/build.json" "$repo_root" <<'PY'
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

base, build_file, repository = sys.argv[1:]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def read(path):
    with opener.open(base + path, timeout=2) as response:
        return json.load(response)
for attempt in range(60):
    try:
        health = read("/healthz")
        break
    except (OSError, urllib.error.URLError):
        time.sleep(0.5)
else:
    raise SystemExit("Hub did not become ready")
source = json.loads(Path(build_file).read_text())["source"]
for key in ("revision", "dirty", "source_fingerprint", "catalog_sha256"):
    if health.get(key) != source[key]:
        raise SystemExit("Hub build provenance mismatch: " + key)
catalog = json.loads((Path(repository) / "cicada-go/internal/clientcontract/catalog.json").read_text())
capability = read("/v2/client/capabilities")
if (health.get("status") != "ok" or capability.get("status") != "partial"
        or capability.get("contract_revision") != catalog["contract_revision"]
        or capability.get("catalog_sha256") != source["catalog_sha256"]):
    raise SystemExit("Hub capability identity mismatch")
PY

phase=protocol_test
set +e
if [[ "$suite" == network-m1 ]]; then
  docker run --rm --name "$test_container" --network host \
    --user "$(id -u):$(id -g)" --env-file "$scratch/test.env" \
    -e "CICADA_TEST_HUB_URL=$hub_url" -e CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3 \
    -e GOCACHE=/tmp/go-build -e GOPROXY=off -e CGO_ENABLED=0 \
    -v "$scratch/state:/tmp/fixture-state" --entrypoint go "$test_image_id" \
    test -json -p=1 ./internal/server -run "$test_selector" -count=1 >"$scratch/test.raw" 2>&1
else
  docker run --rm --name "$test_container" --network host \
    --user "$(id -u):$(id -g)" --env-file "$scratch/test.env" \
    -e "CICADA_TEST_HUB_URL=$hub_url" -e CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3 \
    -e GOCACHE=/tmp/go-build -e GOPROXY=off -e CGO_ENABLED=0 \
    -v "$scratch/state:/tmp/fixture-state" "$test_image_id" >"$scratch/test.raw" 2>&1
fi
test_exit=$?
set -e
# Keep only structured test lifecycle metadata. Failure output can contain a
# decoded fixture or credential; it is never copied into public evidence.
python3 - "$scratch/test.raw" "$output_root/test.log" "$test_exit" "$suite" <<'PY'
import json
from pathlib import Path
import re
import sys

raw, destination, exit_code, suite = sys.argv[1:]
events = []
required = ({"TestNetworkM1DockerHub"} if suite == "network-m1" else
            {"TestClientDockerHubSmoke", "TestClientDockerHubRecoveryFixture"})
passed = set()
for line in Path(raw).read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except ValueError:
        continue
    name, action = event.get("Test", ""), event.get("Action")
    if not re.fullmatch(r"[A-Za-z0-9_/.]+", name) or action not in ("run", "pass", "fail", "skip"):
        continue
    events.append({"test": name, "action": action})
    if action == "pass" and name in required:
        passed.add(name)
events.append({"runner_exit_code": int(exit_code), "required_tests_passed": sorted(passed)})
Path(destination).write_text("".join(json.dumps(event) + "\n" for event in events))
if int(exit_code) != 0 or passed != required:
    raise SystemExit("Required Docker protocol test failed or did not run; inspect sanitized lifecycle evidence")
PY
status=PASS
phase=complete
