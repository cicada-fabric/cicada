#!/usr/bin/env bash
# Disposable Docker network gate for the one-Hub Node topology.
# This checks TCP reachability, not a real Codex runtime or Node authentication.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
for command_name in docker git python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'BLOCKED: required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  printf 'BLOCKED: Docker daemon unavailable\n' >&2
  exit 1
}

scratch="$(mktemp -d "${TMPDIR:-/tmp}/cicada-node-hub-topology.XXXXXXXX")"
chmod 0700 "$scratch"
run_suffix="$(basename "$scratch" | tr -cd '[:alnum:]')-$$"
run_id="cicada-nht-${run_suffix,,}"
hub_container="${run_id}-hub"
node_a_container="${run_id}-node-a"
node_b_container="${run_id}-node-b"
node_a_network="${run_id}-a-net"
node_b_network="${run_id}-b-net"
hub_image="${run_id}:hub"
test_image="${run_id}:test"
hub_image_id=""
test_image_id=""
phase=build

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ "$exit_code" -ne 0 ]]; then
    printf 'FAIL phase=%s exit_code=%s\n' "$phase" "$exit_code" >&2
  fi
  docker rm -f "$node_a_container" "$node_b_container" "$hub_container" >/dev/null 2>&1 || true
  docker network rm "$node_a_network" "$node_b_network" >/dev/null 2>&1 || true
  docker image rm "$test_image" "$hub_image" >/dev/null 2>&1 || true
  if [[ "$exit_code" -ne 0 && -s "$scratch/fake-harness.raw" ]]; then
    local diagnostic
    diagnostic="$(mktemp "${TMPDIR:-/tmp}/cicada-node-hub-topology-failure.XXXXXXXX.log")"
    cp "$scratch/fake-harness.raw" "$diagnostic"
    chmod 0600 "$diagnostic"
    printf 'Private Docker/Go test diagnostics: %s\n' "$diagnostic" >&2
  fi
  rm -rf -- "$scratch"
  exit "$exit_code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

phase=build
"${repo_root}/scripts/build-hub-image.sh" \
  --image "$hub_image" --interop-test-image "$test_image" \
  --metadata-file "$scratch/build.json" >/dev/null
readarray -t image_ids < <(python3 - "$scratch/build.json" <<'PY'
import json
import sys

build = json.load(open(sys.argv[1], encoding="utf-8"))
print(build["image"]["id"])
print(build["test_image"]["id"])
PY
)
hub_image_id="${image_ids[0]}"
test_image_id="${image_ids[1]}"

phase=networks
docker network create --label "org.cicada.test.run=$run_id" "$node_a_network" >/dev/null
docker network create --label "org.cicada.test.run=$run_id" "$node_b_network" >/dev/null
node_a_gateway="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$node_a_network")"
node_b_gateway="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$node_b_network")"

mkdir "$scratch/state" "$scratch/workspaces"
python3 - "$scratch/hub.env" <<'PY'
from pathlib import Path
import secrets
import sys

# This synthetic API token only initializes this throwaway Hub container.
Path(sys.argv[1]).write_text("CICADA_API_TOKEN=" + secrets.token_hex(32) + "\n")
PY

phase=hub_start
docker run --rm -d --name "$hub_container" --network bridge \
  -p "$node_a_gateway::8787" -p "$node_b_gateway::8787" \
  --env-file "$scratch/hub.env" \
  -v "$scratch/state:/state" -v "$scratch/workspaces:/workspace" \
  "$hub_image_id" >/dev/null
hub_bindings="$(docker port "$hub_container" 8787/tcp)"
hub_port_a="$(awk -F: -v address="$node_a_gateway" '$1 == address {print $2}' <<<"$hub_bindings")"
hub_port_b="$(awk -F: -v address="$node_b_gateway" '$1 == address {print $2}' <<<"$hub_bindings")"
mapfile -t hub_binding_lines <<<"$hub_bindings"
if [[ -z "$hub_port_a" || -z "$hub_port_b" || ${#hub_binding_lines[@]} -ne 2 ||
      "$hub_bindings" == *"0.0.0.0:"* ]]; then
  printf 'FAIL phase=%s: Hub port is not limited to the two private Node bridge gateways\n' "$phase" >&2
  exit 1
fi
printf 'PASS: disposable Hub is published only on the two isolated Docker bridge gateways\n'
for attempt in $(seq 1 60); do
  if docker exec "$hub_container" busybox wget -q -T 2 -O /dev/null \
      http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    printf 'FAIL phase=%s: disposable Hub did not become healthy\n' "$phase" >&2
    exit 1
  fi
  sleep 0.5
done

phase=node_start
# Each probe Node is confined to its own Docker bridge. A local TCP listener
# lets the isolation checks distinguish an unreachable peer from no service.
docker run --rm -d --name "$node_a_container" --network "$node_a_network" \
  --add-host "cicada-hub:$node_a_gateway" --entrypoint /bin/sh "$test_image_id" \
  -c 'while :; do busybox nc -l -p 19437 -e /bin/cat >/dev/null 2>&1 || true; done' >/dev/null
docker run --rm -d --name "$node_b_container" --network "$node_b_network" \
  --add-host "cicada-hub:$node_b_gateway" --entrypoint /bin/sh "$test_image_id" \
  -c 'while :; do busybox nc -l -p 19437 -e /bin/cat >/dev/null 2>&1 || true; done' >/dev/null
node_a_ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$node_a_network\").IPAddress}}" "$node_a_container")"
node_b_ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$node_b_network\").IPAddress}}" "$node_b_container")"
node_a_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$node_a_container")"
node_b_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$node_b_container")"
hub_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$hub_container")"
if [[ "$node_a_networks" != "$node_a_network " || "$node_b_networks" != "$node_b_network " ||
      "$hub_networks" != "bridge " ]]; then
  printf 'FAIL phase=node_start: container network attachments differ from the isolated topology\n' >&2
  exit 1
fi

wait_for_listener() {
  local container="$1"
  for attempt in $(seq 1 20); do
    if docker exec "$container" busybox nc -z -w 1 127.0.0.1 19437 >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}
wait_for_listener "$node_a_container" || {
  printf 'FAIL phase=node_start: Node A TCP probe listener did not start\n' >&2
  exit 1
}
wait_for_listener "$node_b_container" || {
  printf 'FAIL phase=node_start: Node B TCP probe listener did not start\n' >&2
  exit 1
}

phase=outbound_hub
for node_container in "$node_a_container" "$node_b_container"; do
  node_hub_port="$hub_port_a"
  if [[ "$node_container" == "$node_b_container" ]]; then
    node_hub_port="$hub_port_b"
  fi
  if ! docker exec "$node_container" busybox wget -q -T 5 -O /dev/null \
      "http://cicada-hub:${node_hub_port}/healthz" >/dev/null 2>&1; then
    printf 'FAIL phase=%s: %s could not make an outbound request to the selected Hub on its bridge gateway\n' \
      "$phase" "$node_container" >&2
    exit 1
  fi
  printf 'PASS: %s initiated TCP/HTTP to the same disposable Hub healthz\n' "$node_container"
done

phase=node_isolation
if docker exec "$node_a_container" busybox nc -z -w 2 "$node_b_ip" 19437 >/dev/null 2>&1; then
  printf 'FAIL phase=%s: Node A established TCP to Node B\n' "$phase" >&2
  exit 1
fi
if docker exec "$node_b_container" busybox nc -z -w 2 "$node_a_ip" 19437 >/dev/null 2>&1; then
  printf 'FAIL phase=%s: Node B established TCP to Node A\n' "$phase" >&2
  exit 1
fi
printf 'PASS: Node A and Node B cannot establish direct TCP in either direction\n'

phase=hub_isolation
if docker exec "$hub_container" busybox nc -z -w 2 "$node_a_ip" 19437 >/dev/null 2>&1; then
  printf 'FAIL phase=%s: Hub established TCP to Node A\n' "$phase" >&2
  exit 1
fi
if docker exec "$hub_container" busybox nc -z -w 2 "$node_b_ip" 19437 >/dev/null 2>&1; then
  printf 'FAIL phase=%s: Hub established TCP to Node B\n' "$phase" >&2
  exit 1
fi
printf 'PASS: Hub cannot establish TCP to either Node listener across Docker bridges\n'

phase=fake_sealed_ask_reply
set +e
docker run --rm --name "${run_id}-fake-harness" --network none \
  --workdir /src -e GOPROXY=off -e GOCACHE=/tmp/go-build -e CGO_ENABLED=0 \
  --entrypoint go "$test_image_id" test -json -p=1 ./cmd/cicada \
  -run '^TestMCPSealedSameGroupCrossNodeAskReplyFullChain$' -count=1 \
  >"$scratch/fake-harness.raw" 2>&1
fake_harness_exit=$?
set -e
python3 - "$scratch/fake-harness.raw" "$fake_harness_exit" <<'PY'
import json
from pathlib import Path
import sys

path, raw_exit = sys.argv[1:]
required = "TestMCPSealedSameGroupCrossNodeAskReplyFullChain"
passed = False
for line in Path(path).read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("Test") == required and event.get("Action") == "pass":
        passed = True
if int(raw_exit) != 0 or not passed:
    raise SystemExit("sealed fake ASK/REPLY harness failed or did not run")
print("PASS: sealed cross-Node fake ASK/REPLY harness (one in-process httptest Hub)")
PY

phase=node_reconnect_tls_integration
set +e
docker run --rm --name "${run_id}-node-reconnect" --network none \
  --workdir /src -e GOPROXY=off -e GOCACHE=/tmp/go-build -e CGO_ENABLED=0 \
  --entrypoint go "$test_image_id" test -json -p=1 ./cmd/cicada \
  -run '^TestMachineRelayReconnectClaimsDurableOfflineMessage$' -count=1 \
  >"$scratch/fake-harness.raw" 2>&1
reconnect_harness_exit=$?
set -e
python3 - "$scratch/fake-harness.raw" "$reconnect_harness_exit" <<'PY'
import json
from pathlib import Path
import sys

path, raw_exit = sys.argv[1:]
required = "TestMachineRelayReconnectClaimsDurableOfflineMessage"
passed = False
for line in Path(path).read_text(errors="replace").splitlines():
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get("Test") == required and event.get("Action") == "pass":
        passed = True
if int(raw_exit) != 0 or not passed:
    raise SystemExit("Node TLS/SSE reconnect integration failed or did not run")
print("PASS: production Node TLS/SSE disconnect, outbound reconnect, durable offline claim, and duplicate-wake dedupe")
PY

phase=complete
python3 - "$scratch/build.json" <<'PY'
import json
import sys

build = json.load(open(sys.argv[1], encoding="utf-8"))
source = build["source"]
print("Build source: revision={} dirty={} fingerprint={}".format(
    source["revision"], str(source["dirty"]).lower(), source["source_fingerprint"]))
print("Images: Hub={} test={}".format(build["image"]["id"], build["test_image"]["id"]))
PY
printf 'Temporary Docker names: hub=%s node-a=%s node-b=%s networks=%s,%s\n' \
  "$hub_container" "$node_a_container" "$node_b_container" \
  "$node_a_network" "$node_b_network"
printf 'NOT_RUN: production Node enrollment/owner confirmation, real Codex runtime, Android, physical multi-host, public HTTPS\n'
printf 'LIMIT: reconnect integration uses the real Hub Fabric handler and SQLite Store in-process over loopback TLS; its Codex queue is fake and it does not launch the full machine-agent process\n'
printf 'LIMIT: Node bridges retain Docker NAT; this gate proves peer/Hub TCP isolation and tested Hub egress, not a general egress allowlist\n'
printf 'PASS: isolated Docker Node-to-Hub topology gate\n'
