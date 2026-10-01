#!/usr/bin/env bash
# Joined V68 integration fixture: two Nodes use separate ordinary Docker
# bridge namespaces and reach the Hub through their gateway mappings; peer
# ports are not published and direct Hub/peer paths are tested for denial.
# The runtime queue executable is a recording fake; this is not model/native
# consumption evidence.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s\n' "${BASH_SOURCE[0]}" >&2
  exit 2
fi
for command_name in docker git python3 sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'BLOCKED: required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  printf 'BLOCKED: Docker daemon unavailable\n' >&2
  exit 1
}

evidence_root="${CICADA_V68_EVIDENCE_ROOT:-${repo_root}/.cicada-data}"
mkdir -p "$evidence_root"
chmod 0700 "$evidence_root"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${evidence_root}/v68-joined-${timestamp}-$$"
mkdir "$evidence_dir"
chmod 0700 "$evidence_dir"
executed_script="${evidence_dir}/executed-script.sh"
cp -- "${BASH_SOURCE[0]}" "$executed_script"
chmod 0600 "$executed_script"
executed_script_sha256="$(sha256sum "$executed_script" | awk '{print $1}')"

uid="$(id -u)"
gid="$(id -g)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/cicada-v68-XXXXXXXX")"
chmod 0700 "$scratch"
suffix="$(basename "$scratch" | tr -cd '[:alnum:]')-$$"
run_id="cicada-v68-${suffix,,}"
hub_container="${run_id}-hub"
node_a_container="${run_id}-node-a"
node_b_container="${run_id}-node-b"
node_a_network="${run_id}-node-a-net"
node_b_network="${run_id}-node-b-net"
hub_image="${run_id}:hub"
test_image="${run_id}:test"
hub_image_id=""
test_image_id=""
build_metadata="${scratch}/build.json"
phase=build
outcome=FAIL
exit_code=1
hub_port_a=""
hub_port_b=""
fixture_json="${scratch}/fixture.json"
node_diagnostic_file="${evidence_dir}/node-binding-diagnostics.jsonl"
question_file="${scratch}/expected-question.txt"
answer_file="${scratch}/expected-answer.txt"
thread_a=""
thread_b=""
node_a_id=""
node_b_id=""
group_id=""
endpoint_a=""
endpoint_b=""
request_id=""
ask_message_id=""
cleanup_ok=true

write_result() {
  local final_outcome="$1" final_exit="$2" final_phase="$3"
  python3 - "$evidence_dir/result.json" "$final_outcome" "$final_exit" "$final_phase" \
    "$executed_script" "$executed_script_sha256" "$build_metadata" "$cleanup_ok" \
    "$node_a_id" "$node_b_id" "$group_id" "$endpoint_a" "$endpoint_b" \
    "$node_diagnostic_file" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

path, outcome, exit_code, phase, script, script_sha256, build_path, cleanup_ok, node_a, node_b, group, ep_a, ep_b, diagnostic_path = sys.argv[1:]
result = {
    "schema": "cicada.v68-joined-result.v1",
    "status": outcome,
    "exit_code": int(exit_code),
    "phase": phase,
    "fixture": "two separate ordinary Docker bridge Node namespaces, one Fabric-only Hub; direct Hub/peer paths denied",
    "network_model": "separate ordinary Docker bridges; NAT-like outbound Hub access; no internal-network claim",
    "control_management_probe": "authenticated HTTP over Hub gateway mapping; /v1/machines returned 503",
    "runtime_queue": "recording fake; no model/native consumption",
    "script_sha256": script_sha256,
    "executed_script": Path(script).name,
    "argv": [],
    "cleanup_owned_containers_and_networks": cleanup_ok == "true",
    "cleanup_owned_scratch": True,
    "protocol_ids": {key: value for key, value in {
        "node_a": node_a, "node_b": node_b, "group_id": group,
        "endpoint_a": ep_a, "endpoint_b": ep_b,
    }.items() if value},
}
try:
    diagnostic_file = Path(diagnostic_path)
    result["node_binding_diagnostics"] = [json.loads(line) for line in diagnostic_file.read_text(encoding="utf-8").splitlines() if line]
except OSError:
    result["node_binding_diagnostics"] = []
try:
    build = json.loads(Path(build_path).read_text(encoding="utf-8"))
    result["source"] = build["source"]
    result["hub_image"] = build["image"]
    result["test_image"] = build["test_image"]
except (OSError, ValueError, KeyError):
    result["build_metadata"] = "not available"
temporary = Path(str(path) + ".tmp")
temporary.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
PY
}

cleanup() {
  exit_code=$?
  trap - EXIT
  if [[ "$exit_code" -ne 0 ]]; then
    printf 'V68 joined fixture stopped at phase=%s exit_code=%s\n' "$phase" "$exit_code" >&2
  fi
  remove_owned_container() {
    local container_name="$1" expected_image="$2" identity
    if ! docker inspect "$container_name" >/dev/null 2>&1; then return 0; fi
    identity="$(docker inspect --format '{{index .Config.Labels "org.cicada.test.run"}} {{.Image}}' "$container_name" 2>/dev/null)" || {
      cleanup_ok=false; return 1;
    }
    if [[ "$identity" != "$run_id $expected_image" ]]; then
      printf 'FAIL: refusing to remove container without the exact fixture label/image: %s\n' "$container_name" >&2
      cleanup_ok=false
      return 1
    fi
    docker rm -f "$container_name" >/dev/null 2>&1 || cleanup_ok=false
  }
  remove_owned_container "$node_a_container" "$test_image_id"
  remove_owned_container "$node_b_container" "$test_image_id"
  remove_owned_container "$hub_container" "$hub_image_id"
  for network_name in "$node_a_network" "$node_b_network"; do
    if docker network inspect "$network_name" >/dev/null 2>&1; then
      network_owner="$(docker network inspect --format '{{index .Labels "org.cicada.test.run"}}' "$network_name" 2>/dev/null)" || {
        cleanup_ok=false; continue;
      }
      if [[ "$network_owner" != "$run_id" ]]; then
        printf 'FAIL: refusing to remove network without the exact fixture label: %s\n' "$network_name" >&2
        cleanup_ok=false
        continue
      fi
      docker network rm "$network_name" >/dev/null 2>&1 || cleanup_ok=false
    fi
  done
  remove_owned_image() {
    local reference="$1" expected_id="$2" identity
    [[ -n "$expected_id" ]] || return 0
    if ! docker image inspect "$reference" >/dev/null 2>&1; then return 0; fi
    identity="$(docker image inspect --format '{{.Id}} {{index .RepoTags 0}}' "$reference" 2>/dev/null)" || {
      cleanup_ok=false; return 1;
    }
    if [[ "$identity" != "$expected_id $reference" ]]; then
      printf 'FAIL: refusing to remove image without the exact fixture identity: %s\n' "$reference" >&2
      cleanup_ok=false
      return 1
    fi
    docker image rm "$reference" >/dev/null 2>&1 || cleanup_ok=false
  }
  remove_owned_image "$test_image" "$test_image_id"
  remove_owned_image "$hub_image" "$hub_image_id"
  for container_name in "$node_a_container" "$node_b_container" "$hub_container"; do
    docker inspect "$container_name" >/dev/null 2>&1 && cleanup_ok=false
  done
  for network_name in "$node_a_network" "$node_b_network"; do
    docker network inspect "$network_name" >/dev/null 2>&1 && cleanup_ok=false
  done
  if [[ "$cleanup_ok" != true ]]; then outcome=FAIL; exit_code=1; fi
  write_result "$outcome" "$exit_code" "$phase"
  scratch_owner="$(stat -c '%u' "$scratch" 2>/dev/null || true)"
  if [[ ! -d "$scratch" || -L "$scratch" || "$scratch_owner" != "$uid" || "$scratch" != "${TMPDIR:-/tmp}/cicada-v68-"* ]] ||
      ! rm -rf -- "$scratch"; then
    cleanup_ok=false
    outcome=FAIL
    exit_code=1
    python3 - "$evidence_dir/result.json" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["status"] = "FAIL"
data["exit_code"] = 1
data["cleanup_owned_scratch"] = False
temporary = path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
PY
  fi
  printf 'V68 result: %s (%s)\n' "$outcome" "$evidence_dir/result.json"
  if [[ "$exit_code" -ne 0 ]]; then exit "$exit_code"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

phase=build
"${repo_root}/scripts/build-hub-image.sh" \
  --image "$hub_image" --interop-test-image "$test_image" \
  --metadata-file "$build_metadata" >/dev/null
readarray -t image_ids < <(python3 - "$build_metadata" <<'PY'
import json
import sys

build = json.load(open(sys.argv[1], encoding="utf-8"))
print(build["image"]["id"])
print(build["test_image"]["id"])
PY
)
hub_image_id="${image_ids[0]}"
test_image_id="${image_ids[1]}"

phase=fixture_files
mkdir -m 0700 "$scratch/hub-state" "$scratch/node-a-codex" "$scratch/node-b-codex" \
  "$scratch/node-a-workspace" "$scratch/node-b-workspace" "$scratch/capture-a" "$scratch/capture-b" \
  "$scratch/node-a-state" "$scratch/node-b-state"
python3 - "$scratch/.cicada-v68-owned" "$suffix" <<'PY'
from pathlib import Path
import sys

marker = Path(sys.argv[1])
marker.write_text("cicada.v68.disposable.v1\n" + sys.argv[2] + "\n", encoding="utf-8")
marker.chmod(0o600)
PY
printf '%s' 'CICADA-V68-PLAINTEXT-NEVER-IN-RELAY: synthetic ASK body' >"$question_file"
printf '%s' 'CICADA-V68-REPLY-ONLY-OPAQUE: synthetic REPLY body' >"$answer_file"
chmod 0600 "$question_file" "$answer_file"
mkdir -m 0700 "$scratch/node-a-codex/sessions" "$scratch/node-b-codex/sessions"
cat >"$scratch/fake-codex.sh" <<'SH'
#!/bin/sh
set -eu
if [ "$#" -ne 5 ] || [ "$1" != queue ] || [ "$2" != --thread ] || [ "$4" != --message ]; then
  exit 64
fi
case "$3" in *[!A-Za-z0-9_-]*|'') exit 64 ;; esac
printf '%s\n' "$3" >>"${V68_CAPTURE_DIR}/calls.log"
printf '%s' "$5" >"${V68_CAPTURE_DIR}/prompt.${3}"
SH
chmod 0700 "$scratch/fake-codex.sh"
docker run --rm --network none --user "${uid}:${gid}" \
  -v "$scratch:/fixture" -w /src \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOCACHE=/tmp/v68-go-cache \
  --entrypoint go "$test_image_id" test -buildvcs=false ./cmd/cicada-v68fixture \
  -run '^TestV68ReplyCorrelationUsesRequestAndAskMessageSeparately$' -count=1
docker run --rm --network none --user "${uid}:${gid}" \
  -v "$scratch:/fixture" -w /src \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOCACHE=/tmp/v68-go-cache \
  --entrypoint go "$test_image_id" build -trimpath -o /fixture/cicada-v68fixture ./cmd/cicada-v68fixture
chmod 0700 "$scratch/cicada-v68fixture"
docker run --rm --network none --user "${uid}:${gid}" \
  -v "$scratch:/fixture" -w /src \
  --entrypoint /fixture/cicada-v68fixture "$test_image_id" bootstrap \
  --db /fixture/hub-state/cicada.sqlite3 --fixture /fixture >/dev/null
thread_a="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1], encoding="utf-8"))["thread_a"])' "$fixture_json")"
thread_b="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1], encoding="utf-8"))["thread_b"])' "$fixture_json")"
python3 - "$scratch" "$thread_a" "$thread_b" <<'PY'
import json
from pathlib import Path
import sys

root, thread_a, thread_b = sys.argv[1:]
for letter, thread in (("a", thread_a), ("b", thread_b)):
    session_dir = Path(root) / f"node-{letter}-codex" / "sessions" / "2026" / "09" / "30"
    session_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = {"type": "session_meta", "payload": {"id": thread,
              "session_id": "session-" + thread, "cwd": "/workspace"}}
    path = session_dir / f"rollout-v68-{letter}.jsonl"
    path.write_text(json.dumps(record, separators=(",", ":")) + "\n", encoding="utf-8")
    path.chmod(0o600)
PY
group_id="$(python3 - "$fixture_json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["group_id"])
PY
)"
node_a_id="$(python3 - "$fixture_json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["node_a"])
PY
)"
hub_id="$(python3 - "$fixture_json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["hub_id"])
PY
)"
node_b_id="$(python3 - "$fixture_json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["node_b"])
PY
)"

phase=isolated_networks
docker network create --driver bridge --label "org.cicada.test.run=$run_id" "$node_a_network" >/dev/null
docker network create --driver bridge --label "org.cicada.test.run=$run_id" "$node_b_network" >/dev/null
node_a_network_internal="$(docker network inspect --format '{{.Internal}}' "$node_a_network")"
node_b_network_internal="$(docker network inspect --format '{{.Internal}}' "$node_b_network")"
if [[ "$node_a_network_internal" != false || "$node_b_network_internal" != false ]]; then
  printf 'FAIL: Node fixtures require separate ordinary Docker bridges, not internal-network mode\n' >&2
  exit 1
fi
gateway_a="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$node_a_network")"
gateway_b="$(docker network inspect --format '{{(index .IPAM.Config 0).Gateway}}' "$node_b_network")"
python3 - "$scratch/hub.env" <<'PY'
from pathlib import Path
import secrets
import sys

Path(sys.argv[1]).write_text("CICADA_API_TOKEN=" + secrets.token_hex(32) + "\n")
Path(sys.argv[1]).chmod(0o600)
PY
phase=hub_start
docker run -d --name "$hub_container" --label "org.cicada.test.run=$run_id" \
  --user "${uid}:${gid}" --network bridge -p "${gateway_a}::8787" -p "${gateway_b}::8787" \
  --env-file "$scratch/hub.env" -e CICADA_STATE_DIR=/state \
  -v "$scratch/hub-state:/state" \
  -v "$scratch/cicada-v68fixture:/usr/local/libexec/cicada-v68fixture:ro" \
  "$hub_image_id" serve --host 0.0.0.0 --port 8787 --fabric-only >/dev/null
refresh_hub_bindings() {
  local previous_a="$hub_port_a" previous_b="$hub_port_b" new_a new_b inspect_summary
  mapfile -t hub_bindings < <(docker port "$hub_container" 8787/tcp)
  new_a="$(python3 - "$gateway_a" "${hub_bindings[@]}" <<'PY'
import sys
gateway, *bindings = sys.argv[1:]
matches = [line.rsplit(":", 1)[1] for line in bindings if line.rsplit(":", 1)[0] == gateway]
if len(matches) != 1:
    raise SystemExit(1)
print(matches[0])
PY
  )"
  new_b="$(python3 - "$gateway_b" "${hub_bindings[@]}" <<'PY'
import sys
gateway, *bindings = sys.argv[1:]
matches = [line.rsplit(":", 1)[1] for line in bindings if line.rsplit(":", 1)[0] == gateway]
if len(matches) != 1:
    raise SystemExit(1)
print(matches[0])
PY
  )"
  hub_port_a="$new_a"
  hub_port_b="$new_b"
  inspect_summary="$(docker inspect --format '{{.Id}}|{{.State.Status}}|{{.State.Running}}|{{.State.ExitCode}}|{{json .HostConfig.PortBindings}}|{{json .NetworkSettings.Ports}}' "$hub_container")"
  python3 - "$evidence_dir/hub-port-bindings.jsonl" "$phase" "$previous_a" "$previous_b" \
    "$gateway_a" "$new_a" "$gateway_b" "$new_b" "$inspect_summary" <<'PY'
import json
import os
import sys
from pathlib import Path

path, phase, previous_a, previous_b, gateway_a, port_a, gateway_b, port_b, inspect = sys.argv[1:]
container_id, status, running, exit_code, configured, published = inspect.split("|", 5)
record = {
    "phase": phase,
    "container_id": container_id,
    "status": status,
    "running": running == "true",
    "exit_code": int(exit_code),
    "previous_gateway_ports": {key: value for key, value in {gateway_a: previous_a, gateway_b: previous_b}.items() if value},
    "current_gateway_ports": {gateway_a: port_a, gateway_b: port_b},
    "host_config_port_bindings": json.loads(configured),
    "network_settings_ports": json.loads(published),
}
target = Path(path)
with target.open("a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\n")
os.chmod(target, 0o600)
print("HUB_PORT_BINDINGS=" + json.dumps({
    "phase": phase, "previous": record["previous_gateway_ports"],
    "current": record["current_gateway_ports"], "container_id": container_id,
    "running": record["running"],
}, sort_keys=True))
PY
}
refresh_hub_bindings
hub_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$hub_container")"
if [[ "$hub_networks" != "bridge " ]]; then
  printf 'FAIL: Hub has unexpected Docker network attachments\n' >&2
  exit 1
fi
probe_control_unavailable() {
  python3 - "$gateway_a" "$hub_port_a" "$scratch/hub.env" <<'PY'
import urllib.error
import urllib.request
import sys

gateway, port, env_path = sys.argv[1:]
token = next(line.split("=", 1)[1].strip() for line in open(env_path, encoding="utf-8")
             if line.startswith("CICADA_API_TOKEN="))
request = urllib.request.Request(f"http://{gateway}:{port}/v1/machines",
    headers={"Authorization": "Bearer " + token})
try:
    response = urllib.request.urlopen(request, timeout=1)
    status = response.status
    response.close()
except urllib.error.HTTPError as error:
    status = error.code
    error.close()
except Exception as error:
    status = 0
    failure = type(error).__name__
else:
    failure = "none"
if status == 503:
    print("control_status=503")
elif status == 0:
    print("control_status=0;error_class=" + failure)
else:
    print("control_status=%d;error_class=http_error" % status)
if status != 503:
    raise SystemExit(1)
PY
}
wait_hub() {
  local last_probe="not_probed" inspect_state log_class
  for attempt in $(seq 1 60); do
    last_probe="$(probe_control_unavailable 2>/dev/null || true)"
    if [[ "$last_probe" == "control_status=503" ]]; then return 0; fi
    sleep 0.25
  done
  inspect_state="$(docker inspect --format '{{.Id}}|{{.State.Status}}|{{.State.Running}}|{{.State.ExitCode}}' "$hub_container" 2>/dev/null || printf 'missing|missing|false|1')"
  log_class="$(docker logs --tail 100 "$hub_container" 2>&1 | python3 -c 'import sys; s=sys.stdin.read().lower();
if "address already in use" in s: c="listen_address_in_use"
elif any(x in s for x in ("permission denied", "unable to open database", "readonly database")): c="state_db_access_failure"
elif "database is locked" in s: c="sqlite_busy"
elif "migration" in s and any(x in s for x in ("failed", "failure", "error")): c="schema_migration_failure"
elif "panic" in s: c="process_panic"
elif "listening on" in s: c="listener_log_present_no_ready_probe"
else: c="no_known_startup_error"
print(c)' || printf 'log_classification_unavailable')"
  python3 - "$evidence_dir/hub-readiness-failure.json" "$last_probe" "$inspect_state" "$log_class" "$hub_port_a" "$hub_port_b" <<'PY'
import json
import os
import sys
from pathlib import Path

path, probe, inspect, log_class, port_a, port_b = sys.argv[1:]
container_id, status, running, exit_code = inspect.split("|", 3)
value = {"last_authenticated_control_probe": probe, "container_id": container_id,
         "container_status": status, "container_running": running == "true",
         "container_exit_code": int(exit_code), "hub_port_a": port_a,
         "hub_port_b": port_b, "fixed_log_class": log_class}
target = Path(path)
target.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
target.chmod(0o600)
print("HUB_READINESS_FAILURE=" + json.dumps(value, sort_keys=True))
PY
  return 1
}
wait_hub || { printf 'FAIL: Fabric-only Hub did not pass its bounded authenticated Control-unavailable readiness probe\n' >&2; exit 1; }

phase=fabric_only_control_absent
if ! control_result="$(probe_control_unavailable)" || [[ "$control_result" != "control_status=503" ]]; then
  printf 'FAIL: authenticated Hub gateway Control probe did not return the expected unavailable status\n' >&2
  exit 1
fi
printf 'CONTROL_ABSENT: authenticated /v1/machines over the Hub gateway returned 503.\n'

phase=node_containers
start_node_container() {
  local label="$1" container="$2" network="$3" node_state="$4" codex_home="$5" workspace="$6" capture="$7"
  docker run -d --name "$container" --user "${uid}:${gid}" \
    --env HTTP_PROXY= --env HTTPS_PROXY= --env ALL_PROXY= \
    --env http_proxy= --env https_proxy= --env all_proxy= \
    --env 'NO_PROXY=*' --env 'no_proxy=*' \
    --label "org.cicada.test.run=$run_id" \
    --network "$network" \
    -v "$node_state:/state" -v "$codex_home:/codex" -v "$workspace:/workspace" \
    -v "$capture:/capture" -v "$scratch/fake-codex.sh:/fake/codex:ro" \
    --entrypoint /bin/sh "$test_image_id" -c 'while :; do sleep 3600; done' >/dev/null
}
start_node_container a "$node_a_container" "$node_a_network" "$scratch/node-a-state" \
  "$scratch/node-a-codex" "$scratch/node-a-workspace" "$scratch/capture-a"
start_node_container b "$node_b_container" "$node_b_network" "$scratch/node-b-state" \
  "$scratch/node-b-codex" "$scratch/node-b-workspace" "$scratch/capture-b"
node_a_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$node_a_container")"
node_b_networks="$(docker inspect --format '{{range $name, $endpoint := .NetworkSettings.Networks}}{{$name}} {{end}}' "$node_b_container")"
if [[ "$node_a_networks" != "$node_a_network " || "$node_b_networks" != "$node_b_network " ]]; then
  printf 'FAIL: a Node is attached outside its single dedicated Docker bridge\n' >&2
  exit 1
fi
node_a_ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$node_a_network\").IPAddress}}" "$node_a_container")"
node_b_ip="$(docker inspect --format "{{(index .NetworkSettings.Networks \"$node_b_network\").IPAddress}}" "$node_b_container")"

proxy_code='import socket,sys,threading
host,port=sys.argv[1],int(sys.argv[2])
def copy(src,dst):
 try:
  while True:
   data=src.recv(65536)
   if not data: break
   dst.sendall(data)
 except OSError: pass
 try: dst.shutdown(socket.SHUT_WR)
 except OSError: pass
def accept(client):
 try: upstream=socket.create_connection((host,port),timeout=5)
 except OSError: client.close(); return
 threading.Thread(target=copy,args=(client,upstream),daemon=True).start()
 copy(upstream,client)
 upstream.close();client.close()
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",8787));s.listen()
while True:
 c,_=s.accept();threading.Thread(target=accept,args=(c,),daemon=True).start()'
listener_code='import socket,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",19437));s.listen()
while True:
 c,_=s.accept();c.close()'

start_node_services() {
  local label="$1" container="$2" node_id="$3" gateway="$4" hub_port="$5" capture="$6"
  docker exec -d "$container" python3 -c "$proxy_code" "$gateway" "$hub_port"
  docker exec -d "$container" python3 -c "$listener_code"
  local proxy_ready=false
  for attempt in $(seq 1 60); do
    if docker exec "$container" python3 -c 'import socket;s=socket.create_connection(("127.0.0.1",8787),timeout=.2);s.close()' >/dev/null 2>&1; then
      proxy_ready=true
      break
    fi
    sleep 0.1
  done
  if [[ "$proxy_ready" != true ]]; then
    printf 'FAIL: Node %s Hub forwarder did not bind its local socket within the bounded startup window\n' "$label" >&2
    return 1
  fi
  local binding_probe events_probe binding_stderr events_stderr
  binding_stderr="${scratch}/binding-${label}.stderr"
  if ! binding_probe="$(python3 "$repo_root/scripts/v68-node-binding-diagnostic.py" \
    --db "$scratch/hub-state/cicada.sqlite3" --node-state "$scratch/node-${label}-state" \
    --node-id "$node_id" --hub-id "$hub_id" 2>"$binding_stderr")"; then
    binding_error_class="$(python3 - "$binding_stderr" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(errors="replace").lower()
if "no such table" in text or "no such column" in text: category = "schema_missing"
elif "locked" in text or "busy" in text: category = "database_busy"
elif "unable to open" in text: category = "database_unavailable"
else: category = "diagnostic_process_failed"
print('{"sqlite_error_class":"' + category + '"}')
PY
)"
    binding_probe="$binding_error_class"
  fi
  if ! python3 -c 'import json,sys;json.loads(sys.argv[1])' "$binding_probe" 2>/dev/null; then
    binding_probe='{"sqlite_error_class":"diagnostic_output_invalid"}'
  fi
  events_stderr="${scratch}/events-${label}.stderr"
  if ! events_probe="$(docker exec -i --env "V68_NODE_ID=$node_id" "$container" python3 - 2>"$events_stderr" <<'PY'
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

node_id = os.environ["V68_NODE_ID"]
token = Path("/state/nodes/node-" + node_id + "/relay.token").read_text(encoding="utf-8").strip()
result = {"http_status": None, "error_class": "", "event_stream_content_type": False,
          "ready_event_received": False, "node_token_present": bool(token)}
request = urllib.request.Request("http://127.0.0.1:8787/v2/relay/nodes/" +
    urllib.parse.quote(node_id, safe="") + "/events", headers={
        "Accept": "text/event-stream", "Authorization": "CicadaNode " + token})
try:
    response = urllib.request.urlopen(request, timeout=4)
    result["http_status"] = response.status
    result["event_stream_content_type"] = response.headers.get("Content-Type", "").lower().startswith("text/event-stream")
    result["ready_event_received"] = response.readline(128).startswith(b"event: ready")
    result["error_class"] = "none" if response.status == 200 else "unexpected_http_status"
    response.close()
except urllib.error.HTTPError as error:
    result["http_status"] = error.code
    result["error_class"] = "unauthorized" if error.code == 401 else ("forbidden" if error.code == 403 else "http_error")
    error.close()
except Exception as error:
    result["error_class"] = type(error).__name__
print(json.dumps(result, sort_keys=True))
PY
)"; then
    events_probe="$(python3 - "$events_stderr" <<'PY'
from pathlib import Path
import sys
text = Path(sys.argv[1]).read_text(errors="replace").lower()
if "not running" in text: category = "node_container_stopped"
elif "no such container" in text: category = "node_container_missing"
elif "permission denied" in text: category = "exec_permission_denied"
else: category = "probe_process_failed"
print('{"http_status":null,"error_class":"' + category + '"}')
PY
)"
  fi
  if ! python3 -c 'import json,sys;json.loads(sys.argv[1])' "$events_probe" 2>/dev/null; then
    events_probe='{"http_status":null,"error_class":"probe_output_invalid"}'
  fi
  python3 - "$node_diagnostic_file" "$node_id" "$binding_probe" "$events_probe" <<'PY'
import json
import os
import sys
from pathlib import Path

path, node_id, binding, events = sys.argv[1:]
record = {"node": node_id, "binding": json.loads(binding), "events_probe": json.loads(events),
          "agent": {"started": False, "exit_code": "not_started"}}
with Path(path).open("a", encoding="utf-8") as output:
    output.write(json.dumps(record, sort_keys=True) + "\n")
os.chmod(path, 0o600)
print("V68 safe pre-start diagnosis: " + json.dumps({"node": node_id, "binding": record["binding"], "events_probe": record["events_probe"]}, sort_keys=True))
PY
  if ! python3 -c 'import json,sys; p=json.loads(sys.argv[1]); raise SystemExit(0 if p.get("http_status")==200 and p.get("event_stream_content_type") and p.get("ready_event_received") else 1)' "$events_probe"; then
    printf 'FAIL: Node %s could not open the authenticated Hub event stream through its dedicated bridge\n' "$label" >&2
    return 1
  fi
  printf 'NODE_TO_HUB: %s authenticated event stream returned 200/ready through its gateway mapping.\n' "$label"
  docker exec -d --env "CICADA_CODEX_BIN=/fake/codex" --env "V68_CAPTURE_DIR=/capture" \
    --env "CODEX_HOME=/codex" \
    --env "CICADA_HUB_ID=$hub_id" \
    "$container" /bin/sh -c \
    '/out/cicada machine agent --id "$1" --control-url http://127.0.0.1:8787 --state-dir /state --interval 1s --relay-only >>/state/agent.log 2>&1; rc=$?; printf "%s\n" "$rc" >/state/agent.exit; exit "$rc"' \
    sh "$node_id"
  python3 - "$node_diagnostic_file" "$node_id" <<'PY'
import json
import os
import sys
from pathlib import Path

path, node_id = sys.argv[1:]
lines = Path(path).read_text(encoding="utf-8").splitlines()
records = [json.loads(line) for line in lines]
for record in reversed(records):
    if record.get("node") == node_id:
        record["agent"] = {"started": True, "exit_code": "running_or_not_observed"}
        break
temporary = Path(str(path) + ".tmp")
temporary.write_text("\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
PY
  for attempt in $(seq 1 60); do
    if docker exec "$container" /bin/sh -c "test -S /state/nodes/node-${node_id}/join.sock" >/dev/null 2>&1; then return 0; fi
    if docker exec "$container" /bin/sh -c 'test -s /state/agent.exit' >/dev/null 2>&1; then break; fi
    sleep 0.25
  done
  local agent_diagnostic
  agent_diagnostic="$(docker exec -i --env "V68_NODE_ID=$node_id" "$container" python3 - <<'PY'
import json
import os
from pathlib import Path

node_id = os.environ["V68_NODE_ID"]
root = Path("/state")
log_path = root / "agent.log"
text = log_path.read_text(errors="replace") if log_path.exists() else ""
lines = [line.lower() for line in text.splitlines()]
patterns = (("connection refused", "connect_refused"), ("no route to host", "no_route"),
            ("unauthorized", "unauthorized"), ("forbidden", "forbidden"),
            ("not owner-bound", "owner_binding"), ("device code", "device_code"),
            ("permission denied", "state_permission"), ("event stream", "event_stream"),
            ("credential", "credential"), ("binding", "binding"))
def classify(line):
    found = [name for needle, name in patterns if needle in line]
    return found[-1] if found else ("other_error" if "error" in line or "failed" in line else "other")
exit_path = root / "agent.exit"
exit_code = exit_path.read_text().strip() if exit_path.is_file() else "not_observed"
socket_path = root / "nodes" / ("node-" + node_id) / "join.sock"
processes = 0
for path in Path("/proc").glob("[0-9]*/cmdline"):
    try:
        argv = path.read_bytes().replace(b"\0", b" ").lower()
    except OSError:
        continue
    if argv.startswith(b"/out/cicada\0") and b"machine agent" in argv and b"--relay-only" in argv:
        processes += 1
print(json.dumps({"agent_log_present": log_path.is_file(), "agent_log_line_count": len(lines),
                  "last_log_category": classify(lines[-1]) if lines else "none",
                  "log_categories": sorted(set(classify(line) for line in lines)),
                  "agent_exit_code": exit_code, "agent_process_count": processes,
                  "join_socket_present": socket_path.exists()}, sort_keys=True))
PY
)"
  python3 - "$node_diagnostic_file" "$node_id" "$agent_diagnostic" <<'PY'
import json
import os
import sys
from pathlib import Path

path, node_id, agent = sys.argv[1:]
records = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines()]
for record in reversed(records):
    if record.get("node") == node_id:
        record["agent"] = json.loads(agent)
        break
temporary = Path(str(path) + ".tmp")
temporary.write_text("\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
print("V68 safe agent diagnosis: " + json.dumps({"node": node_id, "agent": json.loads(agent)}, sort_keys=True))
PY
  printf 'FAIL: relay-only Node agent did not expose its owned local bridge (raw agent logs withheld)\n' >&2
  return 1
}

wait_node_listener() {
  local container="$1"
  for attempt in $(seq 1 30); do
    if docker exec "$container" python3 -c 'import socket; s=socket.create_connection(("127.0.0.1",19437),timeout=.2);s.close()' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_node_services a "$node_a_container" "$node_a_id" "$gateway_a" "$hub_port_a" "$scratch/capture-a"
start_node_services b "$node_b_container" "$node_b_id" "$gateway_b" "$hub_port_b" "$scratch/capture-b"
wait_node_listener "$node_a_container" || { printf 'FAIL: Node A fixture listener did not start\n' >&2; exit 1; }
wait_node_listener "$node_b_container" || { printf 'FAIL: Node B fixture listener did not start\n' >&2; exit 1; }

mcp_call() {
  local container="$1" node_id="$2" thread="$3" code_home="$4" tool="$5" arguments_json="$6"
  MCP_CONTAINER="$container" MCP_NODE_ID="$node_id" MCP_THREAD_ID="$thread" \
    MCP_CODE_HOME="$code_home" MCP_HUB_ID="$hub_id" MCP_EVIDENCE_DIR="$evidence_dir" MCP_TOOL="$tool" \
    MCP_ARGUMENTS="$arguments_json" python3 - <<'PY'
import json
import os
import subprocess
import sys

container = os.environ["MCP_CONTAINER"]
thread = os.environ["MCP_THREAD_ID"]
args = json.loads(os.environ["MCP_ARGUMENTS"])
tool = os.environ["MCP_TOOL"]
values = {
    "CODEX_HOME": "/codex", "CODEX_THREAD_ID": thread,
    "CICADA_HUB_ID": os.environ["MCP_HUB_ID"], "CICADA_HARNESS": "codex",
    "CICADA_MACHINE_ID": os.environ["MCP_NODE_ID"],
    "CICADA_WORKSPACE": "/workspace", "CICADA_NODE_STATE_DIR": "/state",
    "CICADA_MCP_SESSION_STATE_FILE": "/state/mcp/sessions.json",
    "CICADA_API_TOKEN": "", "CICADA_API_TOKEN_FILE": "",
}
request_lines = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": tool, "arguments": args}},
]
input_data = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in request_lines)
command = ["docker", "exec", "-i", "--workdir", "/workspace"]
for key, value in values.items():
    command += ["--env", f"{key}={value}"]
command += [container, "/out/cicada", "mcp", "--api-url", "http://127.0.0.1:8787"]
result = subprocess.run(command, input=input_data, text=True, capture_output=True, timeout=45)
if result.returncode != 0:
    raise SystemExit("MCP fixture process failed; private process output withheld")
response = None
for line in result.stdout.splitlines():
    try:
        item = json.loads(line)
    except ValueError:
        continue
    if item.get("id") == 2:
        response = item
        break

if not isinstance(response, dict) or "error" in response:
    raise SystemExit("MCP fixture call returned no valid response")
tool_result = response.get("result")
if not isinstance(tool_result, dict) or tool_result.get("isError"):
    raise SystemExit("MCP fixture tool call was refused")
value = tool_result.get("structuredContent")
if value is None:
    for block in tool_result.get("content", []):
        if block.get("type") == "text":
            try:
                value = json.loads(block["text"])
            except ValueError:
                pass
            break
if not isinstance(value, dict):
    raise SystemExit("MCP fixture tool result was not structured JSON")
if tool == "cicada_join" and not isinstance(value.get("endpoint"), dict):
    recovery = value.get("join_recovery") if isinstance(value.get("join_recovery"), dict) else {}
    scope = value.get("native_context_scope") if isinstance(value.get("native_context_scope"), dict) else {}
    diagnostic = {
        "classification": "join_recovery" if recovery else "join_result_without_endpoint",
        "result_fields": sorted(value.keys()),
        "recovery_status": recovery.get("status"),
        "recovery_state": recovery.get("recovery_state"),
        "reason_code": recovery.get("reason_code"),
        "scope_type": recovery.get("scope_type"),
        "native_history_coverage": scope.get("native_history_coverage") or recovery.get("native_history_coverage"),
        "scope_accepted": scope.get("accepted"),
        "context_policy": scope.get("context_policy"),
        "shared_memory_risk": scope.get("shared_memory_risk"),
    }
    from pathlib import Path
    diagnostic_path = Path(os.environ["MCP_EVIDENCE_DIR"]) / "join-result-classification.json"
    diagnostic_path.write_text(json.dumps(diagnostic, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    diagnostic_path.chmod(0o600)
    print("MCP_JOIN_CLASSIFICATION=" + json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
    raise SystemExit("MCP Join did not produce an Endpoint; bounded status evidence recorded")
print(json.dumps(value, separators=(",", ":")))
PY
}

phase=real_node_join
join_a="$(mcp_call "$node_a_container" "$node_a_id" "$thread_a" "$scratch/node-a-codex" \
  cicada_join "$(python3 -c 'import json,sys;print(json.dumps({"group_id":sys.argv[1]}))' "$group_id")")"
join_b="$(mcp_call "$node_b_container" "$node_b_id" "$thread_b" "$scratch/node-b-codex" \
  cicada_join "$(python3 -c 'import json,sys;print(json.dumps({"group_id":sys.argv[1]}))' "$group_id")")"
endpoint_a="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["endpoint"]["endpoint_id"])' "$join_a")"
endpoint_b="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["endpoint"]["endpoint_id"])' "$join_b")"
if [[ -z "$endpoint_a" || -z "$endpoint_b" || "$endpoint_a" == "$endpoint_b" ]]; then
  printf 'FAIL: distinct production MCP/Node Join sessions did not return two Endpoint IDs\n' >&2
  exit 1
fi

phase=control_off_topology
# The exact Fabric-only production entry point intentionally constructs only
# server.NewFabricHandler(service, token); no Control/planner/reporter starts.
docker stop "$node_a_container" "$node_b_container" >/dev/null
docker stop "$hub_container" >/dev/null
docker run --rm --network none --user "${uid}:${gid}" \
  -v "$scratch:/fixture" -w /src \
  --entrypoint /fixture/cicada-v68fixture "$test_image_id" approve \
  --db /fixture/hub-state/cicada.sqlite3 --fixture /fixture >/dev/null
docker start "$hub_container" >/dev/null
refresh_hub_bindings
wait_hub || { printf 'FAIL: Fabric-only Hub did not recover the existing trust identity/DB\n' >&2; exit 1; }
docker start "$node_a_container" "$node_b_container" >/dev/null
start_node_services a "$node_a_container" "$node_a_id" "$gateway_a" "$hub_port_a" "$scratch/capture-a"
start_node_services b "$node_b_container" "$node_b_id" "$gateway_b" "$hub_port_b" "$scratch/capture-b"

hub_probe="$(docker exec "$hub_container" /usr/local/libexec/cicada-v68fixture probe --address "${node_a_ip}:19437")"
python3 - "$hub_probe" <<'PY'
import json
import sys
if json.loads(sys.argv[1]) != {"tcp_reachable": False}:
    raise SystemExit("Hub network namespace can reach a Node listener")
PY
peer_probe="$(docker exec "$node_a_container" python3 -c 'import socket,sys;
try:
 socket.create_connection((sys.argv[1],19437),timeout=1)
except OSError:
 raise SystemExit(1)
raise SystemExit(0)' "$node_b_ip" >/dev/null 2>&1; printf '%s' "$?")"
if [[ "$peer_probe" == 0 ]]; then
  printf 'FAIL: Node A connected directly to Node B outside the Hub path\n' >&2
  exit 1
fi
peer_probe="$(docker exec "$node_b_container" python3 -c 'import socket,sys;
try:
 socket.create_connection((sys.argv[1],19437),timeout=1)
except OSError:
 raise SystemExit(1)
raise SystemExit(0)' "$node_a_ip" >/dev/null 2>&1; printf '%s' "$?")"
if [[ "$peer_probe" == 0 ]]; then
  printf 'FAIL: Node B connected directly to Node A outside the Hub path\n' >&2
  exit 1
fi
python3 - "$evidence_dir/network-reachability.json" <<'PY'
import json
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(json.dumps({
    "model": "separate ordinary Docker bridges; no internal-network claim",
    "node_a_to_hub_authenticated_event_stream": "PASS",
    "node_b_to_hub_authenticated_event_stream": "PASS",
    "hub_to_node_listener": "DENIED",
    "node_a_to_node_b_listener": "DENIED",
    "node_b_to_node_a_listener": "DENIED",
    "node_ports_published": False,
}, sort_keys=True, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY

phase=offline_ask_and_wrong_ack
# Keep Node B stopped so the real Node A MCP->Unix bridge->Node crypto->Hub
# route persists a sealed request for a genuinely offline peer.
docker stop "$node_b_container" >/dev/null
question="$(cat "$question_file")"
ask_json="$(python3 - "$endpoint_b" "$question" "$suffix" <<'PY'
import json
import sys
print(json.dumps({"target": sys.argv[1], "question": sys.argv[2],
                  "idempotency_key": "v68-ask-" + sys.argv[3]}, separators=(",", ":")))
PY
)"
ask_result="$(mcp_call "$node_a_container" "$node_a_id" "$thread_a" "$scratch/node-a-codex" cicada_ask "$ask_json")"
request_id="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("request_id",""))' "$ask_result")"
ask_message_id="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("message_id",""))' "$ask_result")"
if [[ "$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("status",""))' "$ask_result")" != SENT ||
      -z "$request_id" || -z "$ask_message_id" ]]; then
  printf 'FAIL: source MCP did not durably accept a sealed offline ASK\n' >&2
  exit 1
fi

# A valid Node bearer is still not authority to submit a user/application ACK.
# This authenticated wrong-layer ACK must be rejected before Store mutation.
docker start "$node_b_container" >/dev/null
docker exec -d "$node_b_container" python3 -c "$proxy_code" "$gateway_b" "$hub_port_b"
join_binding="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("binding_id",""))' "$join_b")"
join_epoch="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("binding_epoch",0))' "$join_b")"
wrong_ack_status="$(docker exec "$node_b_container" python3 -c 'import json,sys,urllib.error,urllib.request
node,endpoint,binding,epoch,message=sys.argv[1:]
token=open("/state/nodes/node-"+node+"/relay.token",encoding="utf-8").read().strip()
body=json.dumps({"attempt_id":"attempt_v68_wrong_ack","message_id":message,"digest":"0"*64,
 "endpoint_id":endpoint,"binding_id":binding,"binding_epoch":int(epoch),
 "layer":"APPLICATION_ACKNOWLEDGED"}).encode()
request=urllib.request.Request("http://127.0.0.1:8787/v2/relay/nodes/"+node+"/receipts",data=body,
 headers={"Authorization":"CicadaNode "+token,"Content-Type":"application/json"},method="POST")
try:
 response=urllib.request.urlopen(request,timeout=5); code=response.status;response.close()
except urllib.error.HTTPError as error: code=error.code;error.close()
print(code)' "$node_b_id" "$endpoint_b" "$join_binding" "$join_epoch" "$ask_message_id")"
if [[ "$wrong_ack_status" != 403 ]]; then
  printf 'FAIL: authenticated Node-level application ACK status=%s, expected 403\n' "$wrong_ack_status" >&2
  exit 1
fi
docker stop "$node_b_container" >/dev/null

phase=hub_db_restart_and_outbox_dedup
docker stop "$hub_container" >/dev/null
docker start "$hub_container" >/dev/null
refresh_hub_bindings
wait_hub || { printf 'FAIL: Hub did not recover the durable offline ASK after restart\n' >&2; exit 1; }
docker stop "$node_a_container" >/dev/null
docker start "$node_a_container" >/dev/null
start_node_services a "$node_a_container" "$node_a_id" "$gateway_a" "$hub_port_a" "$scratch/capture-a"
retry_result="$(mcp_call "$node_a_container" "$node_a_id" "$thread_a" "$scratch/node-a-codex" cicada_ask "$ask_json")"
retry_request_id="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("request_id",""))' "$retry_result")"
retry_message_id="$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("message_id",""))' "$retry_result")"
if [[ "$retry_request_id" != "$request_id" || "$retry_message_id" != "$ask_message_id" ]]; then
  printf 'FAIL: process-restart MCP retry changed the accepted ASK identity\n' >&2
  exit 1
fi

phase=offline_node_reconnect
docker start "$node_b_container" >/dev/null
start_node_services b "$node_b_container" "$node_b_id" "$gateway_b" "$hub_port_b" "$scratch/capture-b"
queue_path="$scratch/capture-b/prompt.${thread_b}"
for attempt in $(seq 1 120); do
  if [[ -s "$queue_path" ]]; then break; fi
  sleep 0.25
done
if [[ ! -s "$queue_path" ]] || ! grep -Fq 'CICADA-V68-PLAINTEXT-NEVER-IN-RELAY' "$queue_path"; then
  printf 'FAIL: reconnected Node B did not decrypt and queue the expected sealed ASK\n' >&2
  exit 1
fi

phase=real_mcp_receive_reply
receive_json="$(mcp_call "$node_b_container" "$node_b_id" "$thread_b" "$scratch/node-b-codex" \
  cicada_receive '{"limit":8}')"
python3 - "$receive_json" "$request_id" "$ask_message_id" <<'PY'
import json
import sys
result, request_id, message_id = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]
messages = result.get("messages", [])
matches = [message for message in messages if message.get("request_id") == request_id]
if len(matches) != 1 or matches[0].get("message_id") != message_id or \
        matches[0].get("kind") != "REQUEST" or \
        "CICADA-V68-PLAINTEXT-NEVER-IN-RELAY" not in matches[0].get("body", ""):
    raise SystemExit("target MCP receive did not expose its exact opened request")
PY
answer="$(cat "$answer_file")"
reply_json="$(python3 - "$request_id" "$answer" <<'PY'
import json
import sys
print(json.dumps({"request_id": sys.argv[1], "body": sys.argv[2]}, separators=(",", ":")))
PY
)"
reply_result="$(mcp_call "$node_b_container" "$node_b_id" "$thread_b" "$scratch/node-b-codex" cicada_reply "$reply_json")"
if [[ "$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("status",""))' "$reply_result")" != SENT ||
      "$(python3 -c 'import json,sys;print(json.loads(sys.argv[1]).get("request_id",""))' "$reply_result")" != "$request_id" ]]; then
  printf 'FAIL: target Node MCP did not submit the exact sealed reply\n' >&2
  exit 1
fi

phase=durable_ciphertext_and_terminal_route
docker stop "$node_a_container" "$node_b_container" "$hub_container" >/dev/null
docker run --rm --network none --user "${uid}:${gid}" \
  -v "$scratch:/fixture" -w /src \
  --entrypoint /fixture/cicada-v68fixture "$test_image_id" check --db /fixture/hub-state/cicada.sqlite3 \
  --fixture /fixture --message-id "$ask_message_id" --request-id "$request_id" \
  --plaintext-file /fixture/expected-question.txt --reply-plaintext-file /fixture/expected-answer.txt \
  >/dev/null
if docker logs "$hub_container" 2>&1 | grep -Fq 'CICADA-V68-PLAINTEXT-NEVER-IN-RELAY'; then
  printf 'FAIL: Hub logs contained the synthetic peer plaintext\n' >&2
  exit 1
fi
if grep -Fq 'CICADA-V68-PLAINTEXT-NEVER-IN-RELAY' "$scratch/node-b-state/agent.log" 2>/dev/null; then
  printf 'FAIL: Node agent log contained the synthetic peer plaintext\n' >&2
  exit 1
fi
call_count="$(wc -l <"$scratch/capture-b/calls.log" | tr -d '[:space:]')"
if [[ "$call_count" != 1 ]]; then
  printf 'FAIL: exact native queue fake was invoked %s times, expected one deduplicated queue acceptance\n' "$call_count" >&2
  exit 1
fi

phase=complete
outcome=PASS
exit_code=0
printf 'PASS: real joined two-Node/one-Hub SEALED ASK/REPLY over separate Docker bridge networks with Hub-only reachability; fabric-only Hub; offline DB restart, local outbox retry, reconnect dedupe and wrong-layer ACK refusal.\n'
printf 'LIMIT: queue executable was a recording fake; no native Codex/LLM consumption or Android/public HTTPS was run.\n'
