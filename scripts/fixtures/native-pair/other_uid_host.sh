#!/usr/bin/env bash
# One bounded probe in the exact running network-none acceptance container.
# The actual Node fixture supplies existing private-file/socket coordinates.
set -euo pipefail
umask 077
if [[ $# != 4 ]]; then
 printf 'Usage: other_uid_host.sh CONTAINER RUN_ID REQUEST_JSON RESULT_JSON\n' >&2; exit 2
fi
container="$1"
run_id="$2"
request="$3"
result="$4"
if [[ "$(id -u):$(id -g)" != 1000:1000 || ! "$run_id" =~ ^run-[A-Za-z0-9-]+$ || "$container" != "cicada-native-pair-${run_id,,}" ]]; then
 printf 'NOT_RUN: exact owned acceptance container and host identity required.\n' >&2; exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
workspace_root="$(dirname "$(dirname "$common_dir")")"
state="$workspace_root/.local/state/native-pair-acceptance/$run_id"
python3 - "$state" "$request" "$result" <<'PY'
import json, os
from pathlib import Path, PurePosixPath
import stat, sys
root, request, result = map(Path, sys.argv[1:])
for path in (request, result):
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to(root) or path == root:
        raise SystemExit('NOT_RUN: probe control path outside owned run')
    for parent in (path.parent, *path.parent.parents):
        if parent.is_symlink():
            raise SystemExit('NOT_RUN: symlink in probe control path')
info = request.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 16384:
    raise SystemExit('NOT_RUN: unsafe probe manifest')
if result.exists() or result.is_symlink():
    raise SystemExit('NOT_RUN: retain original probe result')
spec = json.loads(request.read_bytes())
if spec.get('synthetic') is not True or spec.get('owner_uid') != 1000:
    raise SystemExit('NOT_RUN: synthetic fixture manifest required')
PY
# Inspect only public isolation metadata; never retain container environment or
# inspect another container. Retain cap-drop/no-new-privileges for docker exec.
container_id="$(timeout 10s docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"user":{{json .Config.User}},"image":{{json .Config.Image}},"network":{{json .HostConfig.NetworkMode}},"read_only":{{json .HostConfig.ReadonlyRootfs}},"cap_drop":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}}}' "$container" |
python3 -c '
import json, re, sys
v = json.load(sys.stdin)
valid = (bool(re.fullmatch("[0-9a-f]{64}", v["id"])) and v["name"] == "/" + sys.argv[1] and v["labels"].get("cicada.native-pair.run") == sys.argv[2]
         and v["running"] is True and v["user"] == "1000:1000" and v["network"] == "none"
         and v["read_only"] is True and v["cap_drop"] == ["ALL"]
         and any(x in ("no-new-privileges", "no-new-privileges:true") for x in v["security"])
         and v["image"] == "golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110")
if not valid:
    raise SystemExit("NOT_RUN: container ownership/isolation differs")
print(v["id"])
' "$container" "$run_id")"
temporary="$(mktemp "${result}.next-XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
# A live protected runtime socket can be in the container's private /tmp.
# Verify existence, original ownership and real owner access inside that same
# container; never interpret the socket path as a host /tmp pathname.
timeout --kill-after=5s 45s docker exec -i --user 1000:1000 "$container_id" /usr/bin/python3 /qa/scripts/fixtures/native-pair/other_uid_probe.py --preflight-owner <"$request" >"${temporary}.owner.json" 2>"${temporary}.owner.stderr"
set +e
timeout --kill-after=5s 45s docker exec -i --user 1001:1000 "$container_id" /usr/bin/python3 /qa/scripts/fixtures/native-pair/other_uid_probe.py <"$request" >"$temporary" 2>"${temporary}.stderr"
probe_exit="$?"
set -e
python3 - "$temporary" "$result" "$probe_exit" "$container_id" <<'PY'
import json, os
from pathlib import Path
import sys
temporary, result = map(Path, sys.argv[1:3])
code = int(sys.argv[3])
owner = json.loads(Path(str(temporary) + '.owner.json').read_bytes())
if owner.get('status') != 'OBSERVED_OWNER_ACCESS' or owner.get('uid') != 1000:
    raise SystemExit('NOT_RUN: live original owner precondition missing')
raw = temporary.read_bytes()
if len(raw) > 65536:
    raise SystemExit('NOT_RUN: probe output exceeds bound')
try:
    observation = json.loads(raw)
except ValueError:
    observation = {'status': 'NOT_RUN', 'reason': 'MISSING_ACTUAL_PROBE_RESULT'}
valid = (code == 0 and observation.get('scope') == 'ACTUAL_OTHER_UID_OS_PRIVATE_FILE_AND_IPC_ACCESS_ONLY'
         and observation.get('status') == 'OBSERVED_DENIAL' and observation.get('uid') == 1001
         and observation.get('gid') == 1000 and bool(observation.get('checks'))
         and all(row.get('permission_denied') is True for row in observation['checks']))
record = {'scope': 'OTHER_UID_OS_BOUNDARY_ONLY_NOT_DOMAIN_ACCEPTANCE', 'probe_exit_code': code,
          'status': 'OBSERVED_DENIAL' if valid else 'FAIL', 'observation': observation,
          'owner_precondition': owner, 'container_id': sys.argv[4],
          'domain_context_and_signing': 'NOT_RUN'}
temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
os.link(temporary, result)  # Create-only publication; retain any original result.
raise SystemExit(0 if valid else 1)
PY
