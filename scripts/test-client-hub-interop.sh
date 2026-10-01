#!/usr/bin/env bash
# Disposable real-TCP protocol test; never uses an existing Hub or model runtime.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
suite=client
if [[ "${1:-}" == "--suite" ]]; then
  [[ $# -eq 2 ]] || {
    printf 'Usage: %s [--suite client|network-m1|group-spaces-m2|capacity]\n' "$0" >&2
    exit 2
  }
  suite="$2"
  shift 2
fi
[[ $# -eq 0 ]] || {
  printf 'Usage: %s [--suite client|network-m1|group-spaces-m2|capacity]\n' "$0" >&2
  exit 2
}
case "$suite" in
  client)
    test_selector='^TestClientDockerHub(Smoke|RecoveryFixture)$'
    ;;
  network-m1)
    test_selector='^TestNetworkM1DockerHub$'
    ;;
  group-spaces-m2)
    test_selector='^TestGroupSpacesM2(HTTPHistoryRetentionAndTopicCAS|DockerHub)$'
    ;;
  capacity)
    test_selector='^TestHubBoundedCapacityDocker$'
    ;;
  *)
    printf 'Unknown interop suite: %s\n' "$suite" >&2
    printf 'Usage: %s [--suite client|network-m1|group-spaces-m2|capacity]\n' "$0" >&2
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
if [[ "$suite" == group-spaces-m2 ]]; then default_output_suite=group-spaces-m2-interop; fi
if [[ "$suite" == capacity ]]; then default_output_suite=bounded-capacity-interop; fi
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
  if [[ "$suite" == capacity ]]; then
    [[ ! -f "$scratch/capacity-output/protocol.json" ]] || cp "$scratch/capacity-output/protocol.json" "$output_root/capacity-protocol.json"
    [[ ! -f "$scratch/capacity-output/protocol.json.recovery.json" ]] || cp "$scratch/capacity-output/protocol.json.recovery.json" "$output_root/capacity-recovery.json"
    [[ ! -f "$scratch/capacity-runtime.json" ]] || cp "$scratch/capacity-runtime.json" "$output_root/capacity-runtime.json"
    [[ ! -f "$scratch/capacity-database.json" ]] || cp "$scratch/capacity-database.json" "$output_root/capacity-database.json"
  fi
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
elif suite == "group-spaces-m2":
    schema_version = "cicada.group-spaces-m2-interop.v1"
    test_name = "TestGroupSpacesM2DockerHub"
    level = "real_tcp_disposable_hub_group_spaces_m2"
    scope = ["synthetic_two_node_credentials", "trusted_group_sessions",
             "per_reader_sealed_journal", "self_read_and_peer_read",
             "mismatched_node_session_denial", "topic_status_cas_and_stale_retry",
             "control_management_routes_not_exercised"]
elif suite == "capacity":
    schema_version = "cicada.hub-bounded-capacity.v1"
    test_name = "TestHubBoundedCapacityDocker"
    level = "real_tcp_disposable_hub_bounded_contention_sample"
    scope = ["one_disposable_hub_process", "one_sqlite_state", "two_synthetic_logical_nodes",
             "64_synthetic_endpoints", "16_http_workers", "directory_read", "sealed_send_ask",
             "relay_admission_backpressure", "cancellation_and_reply_progress",
             "not_a_capacity_guarantee", "NATIVE_NOT_RUN"]
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
if suite == "group-spaces-m2":
    result["additional_tests"] = [
        {"name": "TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS", "exit_code": int(test_exit),
         "level": "real_tcp_new_fabric_handler_control_free"},
    ]
    result["native_harness_session"] = "SYNTHETIC_FIXTURE_ONLY"
    result["physical_nodes"] = "NOT_RUN"
if suite == "capacity":
    for key, filename in (("bounded_load", "capacity-protocol.json"),
                          ("recovery", "capacity-recovery.json"),
                          ("hub_runtime", "capacity-runtime.json"),
                          ("persistent_rows", "capacity-database.json")):
        path = Path(output) / filename
        if path.exists():
            result[key] = json.loads(path.read_text())
        else:
            result[key] = None
    result["native_runtime"] = "NATIVE_NOT_RUN"
    result["physical_nodes"] = "NOT_RUN"
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
if [[ "$suite" == capacity ]]; then mkdir "$scratch/capacity-output"; fi
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
if [[ "$suite" == capacity ]]; then
  docker run -d --name "$hub_container" --cpus 1 --memory 128m --memory-swap 128m \
    -p 127.0.0.1::8787 --env-file "$scratch/hub.env" -v "$scratch/state:/state" \
    -v "$scratch/workspaces:/workspace" "$hub_image_id" >/dev/null
else
  docker run --rm -d --name "$hub_container" -p 127.0.0.1::8787 \
    --env-file "$scratch/hub.env" -v "$scratch/state:/state" \
    -v "$scratch/workspaces:/workspace" "$hub_image_id" >/dev/null
fi
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
if [[ "$suite" == network-m1 || "$suite" == group-spaces-m2 ]]; then
  docker run --rm --name "$test_container" --network host \
    --user "$(id -u):$(id -g)" --env-file "$scratch/test.env" \
    -e "CICADA_TEST_HUB_URL=$hub_url" -e CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3 \
    -e GOCACHE=/tmp/go-build -e GOPROXY=off -e CGO_ENABLED=0 \
    -v "$scratch/state:/tmp/fixture-state" --entrypoint go "$test_image_id" \
    test -json -p=1 ./internal/server -run "$test_selector" -count=1 >"$scratch/test.raw" 2>&1
elif [[ "$suite" == capacity ]]; then
  docker run --rm --name "$test_container" --network host \
    --user "$(id -u):$(id -g)" --env-file "$scratch/test.env" \
    -e "CICADA_TEST_HUB_URL=$hub_url" -e CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3 \
    -e CICADA_CAPACITY_RESULT_PATH=/tmp/capacity-output/protocol.json \
    -e GOCACHE=/tmp/go-build -e GOPROXY=off -e CGO_ENABLED=0 \
    -v "$scratch/state:/tmp/fixture-state" -v "$scratch/capacity-output:/tmp/capacity-output" \
    --entrypoint go "$test_image_id" test -json -p=1 ./internal/server \
    -run "$test_selector" -count=1 >"$scratch/test.raw" 2>&1
else
  docker run --rm --name "$test_container" --network host \
    --user "$(id -u):$(id -g)" --env-file "$scratch/test.env" \
    -e "CICADA_TEST_HUB_URL=$hub_url" -e CICADA_TEST_HUB_DB=/tmp/fixture-state/cicada.sqlite3 \
    -e GOCACHE=/tmp/go-build -e GOPROXY=off -e CGO_ENABLED=0 \
    -v "$scratch/state:/tmp/fixture-state" "$test_image_id" >"$scratch/test.raw" 2>&1
fi
test_exit=$?
set -e
if [[ "$suite" == capacity ]]; then
  phase=capacity_measurement
  inspect="$scratch/capacity-inspect.txt"
  if docker inspect --format '{{.State.Running}}|{{.State.OOMKilled}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.State.Pid}}' \
      "$hub_container" >"$inspect" 2>/dev/null; then
    IFS='|' read -r hub_running hub_oom hub_nano_cpus hub_memory hub_memory_swap hub_pid <"$inspect"
  else
    hub_running=false; hub_oom=unknown; hub_nano_cpus=0; hub_memory=0; hub_memory_swap=0; hub_pid=0
  fi
  peak_rss_kib=""
  if [[ "$hub_pid" =~ ^[1-9][0-9]*$ && -r "/proc/${hub_pid}/status" ]]; then
    peak_rss_kib="$(awk '$1 == "VmHWM:" { print $2 }' "/proc/${hub_pid}/status" 2>/dev/null || true)"
  fi
  python3 - "$scratch/capacity-runtime.json" "$hub_running" "$hub_oom" \
    "$hub_nano_cpus" "$hub_memory" "$hub_memory_swap" "$peak_rss_kib" <<'PY'
import json
from pathlib import Path
import sys

path, running, oom, nano_cpus, memory, memory_swap, peak_rss = sys.argv[1:]
def integer(value):
    try:
        return int(value)
    except ValueError:
        return None
result = {
    "hub_running_after_test": running == "true",
    "oom_killed": True if oom == "true" else (False if oom == "false" else None),
    "cpu_limit_nano_cpus": integer(nano_cpus),
    "cpu_limit_cores": (integer(nano_cpus) / 1_000_000_000) if integer(nano_cpus) is not None else None,
    "memory_limit_bytes": integer(memory),
    "memory_swap_limit_bytes": integer(memory_swap),
    "hub_process_peak_rss_kib_vmhwm": integer(peak_rss),
    "peak_rss_source": "host /proc/<container-init-pid>/status VmHWM",
}
Path(path).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
  python3 - "$scratch/state/cicada.sqlite3" "$scratch/capacity-database.json" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

database, output = sys.argv[1:]
connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True, timeout=5)
try:
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    names = ("fabric_endpoints", "endpoint_group_memberships", "fabric_messages",
             "relay_v2_message_security", "relay_v2_requests", "relay_v2_outbox",
             "relay_v2_inbox", "relay_v2_delivery_attempts", "relay_v2_receipts",
             "relay_v2_request_events")
    counts = {name: (connection.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                     if name in tables else None) for name in names}
finally:
    connection.close()
result = {"database_bytes": Path(database).stat().st_size, "row_counts": counts}
Path(output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
PY
fi
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
            ({"TestGroupSpacesM2DockerHub", "TestGroupSpacesM2HTTPHistoryRetentionAndTopicCAS"}
             if suite == "group-spaces-m2" else
             ({"TestHubBoundedCapacityDocker"} if suite == "capacity" else
             {"TestClientDockerHubSmoke", "TestClientDockerHubRecoveryFixture"}))
            )
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
if [[ "$suite" == capacity ]]; then
  python3 - "$scratch/capacity-runtime.json" "$scratch/capacity-database.json" <<'PY'
import json
import sys
from pathlib import Path

runtime = json.loads(Path(sys.argv[1]).read_text())
database = json.loads(Path(sys.argv[2]).read_text())
counts = database["row_counts"]
required_tables = ("fabric_endpoints", "endpoint_group_memberships", "fabric_messages",
                   "relay_v2_message_security", "relay_v2_requests", "relay_v2_outbox")
if (runtime.get("cpu_limit_nano_cpus") != 1_000_000_000
        or runtime.get("memory_limit_bytes") != 134_217_728
        or runtime.get("memory_swap_limit_bytes") != 134_217_728
        or runtime.get("oom_killed") is not False
        or not isinstance(runtime.get("hub_process_peak_rss_kib_vmhwm"), int)
        or not all(isinstance(counts.get(name), int) for name in required_tables)):
    raise SystemExit("capacity resource measurement incomplete or Hub failed")
PY
fi
status=PASS
phase=complete
