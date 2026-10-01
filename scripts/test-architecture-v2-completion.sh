#!/usr/bin/env bash
# Layered Architecture v2 acceptance orchestrator. Child drivers own their
# disposable fixtures; this wrapper never selects a resident Hub or its state.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
run_native=false
case "${1:-}" in
  "") ;;
  --native) run_native=true; shift ;;
  --help|-h)
    cat <<'EOF'
Usage: scripts/test-architecture-v2-completion.sh [--native]

Runs the existing disposable Client, Network M1, Group Spaces M2, joined V68,
multi-Hub, Node Control (when present), and pinned browser gates in sequence.
Each child creates and removes only its own fixtures. Android, physical-device,
public-HTTPS, and native-model results remain separately recorded. The paid
Codex/native gate is NOT_RUN unless --native is explicitly supplied together
with CICADA_NATIVE_ENV_FILE and CICADA_NATIVE_CODEX_IMAGE.

The browser gate requires CICADA_HUB_IMAGE, CICADA_BUILD_METADATA, and
CICADA_EXPECT_SOURCE_FINGERPRINT. The browser driver verifies that they identify
one immutable candidate image. The optional paid `--native` gate exercises the
Node Worker -> approval -> result path only; it does not cover peer Ask/Reply or
broadcast consumption. Those peer-native results remain NOT_RUN.

Optional: CICADA_COMPLETION_EVIDENCE_ROOT (default .cicada-data/architecture-v2-completion).
EOF
    exit 0
    ;;
  *)
    printf 'Unknown argument: %s\n' "$1" >&2
    printf 'Usage: %s [--native]\n' "$0" >&2
    exit 2
    ;;
esac
[[ $# -eq 0 ]] || { printf 'Unexpected arguments\n' >&2; exit 2; }

for command_name in python3 git sha256sum rg; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'BLOCKED: required command unavailable: %s\n' "$command_name" >&2
    exit 2
  }
done

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_parent="${CICADA_COMPLETION_EVIDENCE_ROOT:-${repo_root}/.cicada-data/architecture-v2-completion}"
mkdir -p "$evidence_parent"
chmod 0700 "$evidence_parent"
evidence_dir="${evidence_parent}/${timestamp}-$$"
mkdir -m 0700 "$evidence_dir"
mkdir -m 0700 "$evidence_dir/logs" "$evidence_dir/scripts"
records="${evidence_dir}/steps.jsonl"
: >"$records"
chmod 0600 "$records"

driver_sha="$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
cp -- "${BASH_SOURCE[0]}" "${evidence_dir}/scripts/test-architecture-v2-completion.sh"
chmod 0600 "${evidence_dir}/scripts/test-architecture-v2-completion.sh"

record() {
  local name="$1" status="$2" rc="$3" phase="$4" entry="$5" script_sha="$6" log="$7" note="$8"
  python3 - "$records" "$name" "$status" "$rc" "$phase" "$entry" "$script_sha" "$log" "$note" <<'PY'
import json, sys
from pathlib import Path
destination, name, status, rc, phase, entry, script_sha, log, note = sys.argv[1:]
item = {"gate": name, "status": status, "exit_code": int(rc),
        "phase": phase, "entrypoint": entry, "script_sha256": script_sha or None,
        "private_log": log or None, "note": note or None}
with Path(destination).open("a", encoding="utf-8") as output:
    output.write(json.dumps(item, sort_keys=True) + "\n")
PY
}

run_gate() {
  local name="$1" script="$2" phase="$3"
  shift 3
  local log="${evidence_dir}/logs/${name}.log"
  local script_sha=""
  if [[ ! -f "$script" ]]; then
    record "$name" NOT_RUN 0 "$phase" "$script" "" "" "gate script is not present in this source snapshot"
    printf '%-24s %s\n' "$name" NOT_RUN
    return 0
  fi
  script_sha="$(sha256sum "$script" | awk '{print $1}')"
  cp -- "$script" "${evidence_dir}/scripts/${name}-$(basename "$script")"
  chmod 0600 "${evidence_dir}/scripts/${name}-$(basename "$script")"
  printf 'RUN %s\n' "$name"
  set +e
  "$@" >"$log" 2>&1
  local rc=$?
  set -e
  chmod 0600 "$log"
  local status=PASS note=""
  if rg -q '^NOT_RUN:' "$log"; then
    status=NOT_RUN
    note="child explicitly reported that its gate did not run"
  elif [[ "$rc" -ne 0 ]]; then
    status=FAIL
    if rg -q '(^|[[:space:]])BLOCKED(:|[[:space:]])|^BLOCKED:' "$log"; then
      status=BLOCKED
      note="child reported an unavailable prerequisite or fixture"
    else
      note="child exited nonzero; inspect its private evidence and log"
    fi
  fi
  if [[ "$name" == "node-control-v1" ]]; then
    local child_summary child_status child_result child_reason
    if [[ -f "${repo_root}/scripts/completion_driver_status.py" ]]; then
      child_summary="$(python3 "${repo_root}/scripts/completion_driver_status.py" "$log" "$rc")"
      child_status="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("status", "FAIL"))' "$child_summary")"
      child_result="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("result_path") or "")' "$child_summary")"
      child_reason="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get("reason", "invalid child status"))' "$child_summary")"
      status="$child_status"
      note="Node Control child status: ${child_reason}"
      if [[ -n "$child_result" ]]; then
        note+=" (${child_result})"
      fi
      if [[ "$status" == "PASS" ]]; then
        note+="; native agent/runtime remain NOT_RUN"
      fi
    else
      status=FAIL
      note="Node Control status parser is missing from this source snapshot"
    fi
  fi
  record "$name" "$status" "$rc" "$phase" "$script" "$script_sha" "$log" "$note"
  printf '%-24s %s (exit %s)\n' "$name" "$status" "$rc"
}

source_before="${evidence_dir}/source-before.json"
source_after="${evidence_dir}/source-after.json"
source_before_status=NOT_RUN
if [[ -x "${repo_root}/scripts/build-hub-image.sh" ]]; then
  set +e
  "${repo_root}/scripts/build-hub-image.sh" --source-info-only --metadata-file "$source_before" \
    >"${evidence_dir}/logs/source-before.log" 2>&1
  source_rc=$?
  set -e
  if [[ "$source_rc" -eq 0 && -f "$source_before" ]]; then
    chmod 0600 "$source_before" "${evidence_dir}/logs/source-before.log"
    source_before_status=CAPTURED
  else
    source_before_status=FAIL
  fi
fi

docker_available=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker_available=true
fi

if [[ "$docker_available" == true ]]; then
  run_gate client-hub "${repo_root}/scripts/test-client-hub-interop.sh" disposable_client \
    bash "${repo_root}/scripts/test-client-hub-interop.sh" --suite client
  run_gate network-m1 "${repo_root}/scripts/test-client-hub-interop.sh" disposable_network_m1 \
    bash "${repo_root}/scripts/test-client-hub-interop.sh" --suite network-m1
  run_gate group-spaces-m2 "${repo_root}/scripts/test-client-hub-interop.sh" disposable_group_spaces_m2 \
    bash "${repo_root}/scripts/test-client-hub-interop.sh" --suite group-spaces-m2
  export CICADA_V68_EVIDENCE_ROOT="${evidence_dir}/v68"
  run_gate joined-v68 "${repo_root}/scripts/test-joined-v68-docker.sh" joined_two_private_nodes_one_hub \
    bash "${repo_root}/scripts/test-joined-v68-docker.sh"
  run_gate multi-hub "${repo_root}/scripts/test-multi-hub-services.sh" multi_hub_services \
    bash "${repo_root}/scripts/test-multi-hub-services.sh"
else
  for name in client-hub network-m1 group-spaces-m2 joined-v68 multi-hub; do
    record "$name" BLOCKED 2 docker_prerequisite "" "" "" "Docker daemon unavailable; child gate not started"
    printf '%-24s BLOCKED\n' "$name"
  done
fi

if [[ -n "${CICADA_HUB_IMAGE:-}" && -n "${CICADA_BUILD_METADATA:-}" &&
      -n "${CICADA_EXPECT_SOURCE_FINGERPRINT:-}" ]]; then
  if [[ "$docker_available" == true ]] && command -v node >/dev/null 2>&1; then
    run_gate hub-web-browser "${repo_root}/scripts/test-hub-web-panel-browser.mjs" pinned_headless_chromium \
      node "${repo_root}/scripts/test-hub-web-panel-browser.mjs"
  else
    record hub-web-browser BLOCKED 2 pinned_headless_chromium "" "" "" "Docker or Node 24 runtime unavailable; browser fixture not started"
    printf '%-24s BLOCKED\n' hub-web-browser
  fi
else
  record hub-web-browser NOT_RUN 0 pinned_headless_chromium "${repo_root}/scripts/test-hub-web-panel-browser.mjs" "" "" \
    "requires explicit CICADA_HUB_IMAGE, CICADA_BUILD_METADATA, and CICADA_EXPECT_SOURCE_FINGERPRINT"
  printf '%-24s NOT_RUN\n' hub-web-browser
fi

node_control_script="${repo_root}/scripts/test-node-control-v1-flow.py"
if [[ -f "$node_control_script" ]]; then
  if [[ "$docker_available" == true ]]; then
    run_gate node-control-v1 "$node_control_script" node_control_pairing_rpc_and_snapshot \
      env CICADA_NODE_CONTROL_V1_ENABLED=1 python3 "$node_control_script"
  else
    record node-control-v1 BLOCKED 2 node_control_pairing_rpc_and_snapshot "$node_control_script" "" "" "Docker daemon unavailable; fixture not started"
    printf '%-24s BLOCKED\n' node-control-v1
  fi
else
  record node-control-v1 NOT_RUN 0 node_control_pairing_rpc_and_snapshot "$node_control_script" "" "" "independent Node Control driver is not present in this source snapshot"
  printf '%-24s NOT_RUN\n' node-control-v1
fi

if [[ "$run_native" == true ]]; then
  native_script="${repo_root}/scripts/test-real-node-codex-approval.py"
  if [[ -z "${CICADA_NATIVE_ENV_FILE:-}" || ! -f "${CICADA_NATIVE_ENV_FILE}" || -z "${CICADA_NATIVE_CODEX_IMAGE:-}" ]]; then
    record native-worker-approval BLOCKED 2 explicit_worker_approval_model_gate "$native_script" "" "" \
      "--native requires a protected CICADA_NATIVE_ENV_FILE and explicit CICADA_NATIVE_CODEX_IMAGE"
    printf '%-24s BLOCKED\n' native-worker-approval
  elif [[ "$docker_available" == true ]]; then
    run_gate native-worker-approval "$native_script" explicit_codex_worker_approval \
      python3 "$native_script" --env-file "$CICADA_NATIVE_ENV_FILE" \
        --image "$CICADA_NATIVE_CODEX_IMAGE" --proxy "${CICADA_NATIVE_PROXY:-http://127.0.0.1:7890}" \
        --output "${evidence_dir}/native-result.json"
  else
    record native-worker-approval BLOCKED 2 explicit_worker_approval_model_gate "$native_script" "" "" "Docker daemon unavailable; native fixture not started"
    printf '%-24s BLOCKED\n' native-worker-approval
  fi
else
  record native-worker-approval NOT_RUN 0 explicit_codex_worker_approval "scripts/test-real-node-codex-approval.py" "" "" "paid Worker approval gate requires explicit --native"
  printf '%-24s NOT_RUN\n' native-worker-approval
fi

source_after_status=NOT_RUN
if [[ -x "${repo_root}/scripts/build-hub-image.sh" ]]; then
  set +e
  "${repo_root}/scripts/build-hub-image.sh" --source-info-only --metadata-file "$source_after" \
    >"${evidence_dir}/logs/source-after.log" 2>&1
  source_rc=$?
  set -e
  if [[ "$source_rc" -eq 0 && -f "$source_after" ]]; then
    chmod 0600 "$source_after" "${evidence_dir}/logs/source-after.log"
    source_after_status=CAPTURED
  else
    source_after_status=FAIL
  fi
fi

driver_after_sha="$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
python3 - "$evidence_dir" "$records" "$driver_sha" "$driver_after_sha" \
  "$source_before_status" "$source_after_status" "$run_native" <<'PY'
import datetime, json, sys
from pathlib import Path
root, records_path, driver_before, driver_after, source_before, source_after, native = sys.argv[1:]
root = Path(root)
steps = [json.loads(line) for line in Path(records_path).read_text().splitlines() if line]
statuses = {step["status"] for step in steps}
source_stable = None
if source_before == "CAPTURED" and source_after == "CAPTURED":
    before = json.loads((root / "source-before.json").read_text()).get("source")
    after = json.loads((root / "source-after.json").read_text()).get("source")
    source_stable = before == after
if "FAIL" in statuses or driver_before != driver_after or source_stable is False:
    overall = "FAIL"
elif "BLOCKED" in statuses or source_before == "FAIL" or source_after == "FAIL":
    overall = "BLOCKED"
elif "NOT_RUN" in statuses:
    overall = "INCOMPLETE"
else:
    overall = "PASS"
result = {
    "schema_version": "cicada.architecture-v2-completion-run.v1",
    "overall_status": overall,
    "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "driver_script_sha256_start": driver_before,
    "driver_script_sha256_end": driver_after,
    "source_metadata_before": "source-before.json" if source_before == "CAPTURED" else source_before,
    "source_metadata_after": "source-after.json" if source_after == "CAPTURED" else source_after,
    "source_identity_unchanged_during_run": source_stable,
    "steps": steps,
    "android": "NOT_RUN",
    "physical_devices": "NOT_RUN",
    "public_https": "NOT_RUN",
    "native_worker_approval_requested": native == "true",
    "native_worker_approval": next((step["status"] for step in steps if step["gate"] == "native-worker-approval"), "NOT_RUN"),
    "native_peer_ask_reply": "NOT_RUN",
    "native_peer_broadcast_consumption": "NOT_RUN",
    "native_scope_note": "The optional real Codex gate covers Worker execution, approval and result reporting only; it is not a peer messaging consumption gate.",
    "fixture_policy": "child drivers own one-shot disposable fixtures; resident containers/state are never selected",
}
tmp = root / "result.json.tmp"
tmp.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
tmp.chmod(0o600)
tmp.replace(root / "result.json")
print(f"{overall}: {root / 'result.json'}")
PY

overall="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["overall_status"])' "${evidence_dir}/result.json")"
[[ "$overall" == PASS ]] || exit 1
