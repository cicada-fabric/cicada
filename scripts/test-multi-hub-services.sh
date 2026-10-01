#!/usr/bin/env bash
# Focused M5 gate: one multi-Hub relay-only Agent against two independent
# production Fabric handlers backed by separate SQLite stores.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
script_path="${repo_root}/scripts/test-multi-hub-services.sh"
golang_image="${CICADA_M5_GOLANG_IMAGE:-golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195}"
module_cache="${CICADA_GOMODCACHE:-${repo_root}/.cicada-data/m1-gomodcache}"

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
[[ -d "$module_cache" ]] || {
  printf 'BLOCKED: Go module cache is missing; set CICADA_GOMODCACHE\n' >&2
  exit 1
}
if ! docker image inspect "$golang_image" >/dev/null 2>&1; then
  docker pull "$golang_image" >/dev/null
fi

run_stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence_dir="${repo_root}/.cicada-data/m5-multihub-${run_stamp}"
mkdir -m 0700 "$evidence_dir"
script_sha256="$(sha256sum "$script_path" | cut -d ' ' -f 1)"
source_before="${evidence_dir}/source-before.json"
source_after="${evidence_dir}/source-after.json"
go_log="${evidence_dir}/focused-go-tests.log"

"${repo_root}/scripts/build-hub-image.sh" --source-info-only --metadata-file "$source_before" >/dev/null
chmod 0600 "$source_before"

phase=focused_go_tests
set +e
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "${repo_root}/cicada-go:/repo:ro" \
  -v "${module_cache}:/gomod:ro" -w /repo \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOMODCACHE=/gomod -e GOCACHE=/tmp/cicada-go-cache \
  "$golang_image" go test -count=1 -v ./cmd/cicada ./internal/nodelock \
  -run '^(TestMachineMultiHubAgentUsesTwoIndependentProductionFabricServices|TestMachineHubContextPinsNodeTokenAndOrigin|TestMachineTwoHubHTTPNodeCredentialsStayIndependent|TestMachineNativeQueueOutcomeSurvivesAttemptAndBlocksUncertainRetry|TestNativeWriterSerializesAcrossHubScopesAndPersistsEpoch)$' \
  2>&1 | tee "$go_log"
test_status=${PIPESTATUS[0]}
set -e
chmod 0600 "$go_log"

"${repo_root}/scripts/build-hub-image.sh" --source-info-only --metadata-file "$source_after" >/dev/null
chmod 0600 "$source_after"

outcome=PASS
if [[ "$test_status" -ne 0 ]]; then outcome=FAIL; fi
if ! python3 - "$source_before" "$source_after" "$go_log" <<'PY'
import json
from pathlib import Path
import re
import sys

before = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
after = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
if before.get("source") != after.get("source"):
    raise SystemExit("source changed during M5 tests")
log = Path(sys.argv[3]).read_text(encoding="utf-8", errors="replace")
expected = {
    "TestMachineMultiHubAgentUsesTwoIndependentProductionFabricServices",
    "TestMachineHubContextPinsNodeTokenAndOrigin",
    "TestMachineTwoHubHTTPNodeCredentialsStayIndependent",
    "TestMachineNativeQueueOutcomeSurvivesAttemptAndBlocksUncertainRetry",
    "TestNativeWriterSerializesAcrossHubScopesAndPersistsEpoch",
}
passed = set(re.findall(r"--- PASS: (Test[A-Za-z0-9_]+)", log))
missing = sorted(expected - passed)
if missing:
    raise SystemExit("focused Go invocation did not execute every required test: " + ", ".join(missing))
PY
then outcome=FAIL; fi

python3 - "$evidence_dir/result.json" "$source_before" "$script_sha256" "$outcome" "$test_status" "$go_log" <<'PY'
import json
import sys
from pathlib import Path

result_path, source_path, script_sha, outcome, test_status, log_path = sys.argv[1:]
source = json.loads(Path(source_path).read_text(encoding="utf-8"))
result = {
    "schema": "cicada.m5-multihub-services.v1",
    "outcome": outcome,
    "go_test_exit_code": int(test_status),
    "source": source["source"],
    "script_sha256": script_sha,
    "focused_log": Path(log_path).name,
    "fixture": "two independent production Fabric HTTP handlers and SQLite stores in one Go process; one production multi-Hub relay-only Agent",
    "coverage": [
        "per-Hub owner-bound Node credential and API-origin pin",
        "cross-Hub credential transplant rejected by a production HTTP handler",
        "Hub A outage does not stop Hub B heartbeat and relay claim reconciliation",
        "per-Hub local replay database restart using synthetic collision IDs",
        "shared native writer lock/epoch and bounded fake queue uncertainty tests",
        "Control management route unavailable in Fabric-only handler",
    ],
    "not_claimed": [
        "separate Hub processes or Docker network namespaces",
        "native Runtime or model consumption",
        "Android or public HTTPS",
    ],
}
path = Path(result_path)
path.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
path.chmod(0o600)
PY

printf 'M5 service gate %s: %s\n' "$outcome" "$evidence_dir/result.json"
if [[ "$outcome" != PASS ]]; then exit 1; fi
