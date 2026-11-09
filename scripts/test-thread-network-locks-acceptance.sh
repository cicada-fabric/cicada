#!/usr/bin/env bash
# Scoped real-crypto/SQLite/TCP QA; no installed Runtime or deployment access.
set -euo pipefail
umask 0077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_cache=""
evidence=""
build_cache=""
image="golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110"
while (($#)); do
 case "$1" in
  --module-cache) module_cache="${2:?missing module cache}"; shift 2 ;;
  --evidence) evidence="${2:?missing new evidence directory}"; shift 2 ;;
  --build-cache) build_cache="${2:?missing task build cache}"; shift 2 ;;
  --image) image="${2:?missing immutable offline image}"; shift 2 ;;
  *) printf 'Usage: %s --module-cache ABS_DIR --evidence NEW_ABS_DIR [--build-cache TASK_ABS_DIR] [--image IMMUTABLE_IMAGE]\n' "$0" >&2; exit 2 ;;
 esac
done
[[ "$module_cache" == /* && -d "$module_cache" && "$evidence" == /* && ! -e "$evidence" ]] || { echo 'Require an existing absolute module cache and a new absolute evidence directory.' >&2; exit 2; }
[[ "$image" == *@sha256:* || "$image" == sha256:* ]] || { echo 'Require an immutable image digest.' >&2; exit 2; }
case "$evidence" in "$repo_root"|"$repo_root"/*) echo 'Evidence must be outside the checkout.' >&2; exit 2 ;; esac
docker image inspect "$image" >/dev/null
mkdir -m 700 "$evidence"
mkdir -m 700 "$evidence/output"
cp "${BASH_SOURCE[0]}" "$evidence/test-thread-network-locks-acceptance.sh"
if [[ -z "$build_cache" ]]; then build_cache="$evidence/go-build"; fi
[[ "$build_cache" == /* ]] || { echo 'Build cache must be an absolute task-owned path.' >&2; exit 2; }
case "$build_cache" in "$repo_root"|"$repo_root"/*) echo 'Build cache must be outside the checkout.' >&2; exit 2 ;; esac
mkdir -p -m 700 "$build_cache"
exec 9>"$build_cache/thread-network-acceptance.lock"
flock -n 9 || { echo 'Task build cache is already in use.' >&2; exit 2; }
snapshot() {
 python3 - "$repo_root" "$1" <<'PY'
import hashlib,json,sys
from pathlib import Path
repo=Path(sys.argv[1])
files={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((repo/'cicada-go').rglob('*')) if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum'))}
Path(sys.argv[2]).write_text(json.dumps(files,sort_keys=True,indent=2)+'\n')
PY
}
snapshot "$evidence/source-before.json"
git -C "$repo_root" rev-parse HEAD >"$evidence/source-head.txt"
git -C "$repo_root" status --short >"$evidence/git-status.txt"
args=(docker run --rm --network none --label cicada.task=thread-network-locks-acceptance
 --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
 -e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off -e CGO_ENABLED=0
 -e GOMODCACHE=/gomodcache -e GOCACHE=/gocache -e CICADA_THREAD_SCOPE_OUTPUT=/out
 --mount "type=bind,src=$repo_root,dst=/repo,readonly"
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
 --mount "type=bind,src=$build_cache,dst=/gocache"
 --mount "type=bind,src=$evidence/output,dst=/out"
 --workdir /repo/cicada-go "$image"
 go test -json -mod=readonly -p=1 -count=1 -tags=cicada_scoped_app_integration -timeout=240s
 ./internal/hubaccountwire ./cmd/cicada
 -run '^TestAcceptance(GroupLock|ThreadOwnerProof|ThreadAuthorityWitness|ThreadSameSID|ThreadLostJoin)')
python3 - "$evidence/argv.json" "${args[@]}" <<'PY'
import json,sys
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps(sys.argv[2:],indent=2)+'\n')
PY
set +e
"${args[@]}" >"$evidence/tests.jsonl" 2>&1
status=$?
set -e
snapshot "$evidence/source-after.json"
python3 - "$evidence" "$status" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1]);status=int(sys.argv[2]);events=[]
for line in (root/'tests.jsonl').read_text().splitlines():
 try: event=json.loads(line)
 except ValueError: continue
 if event.get('Test') and event.get('Action') in ('pass','fail','skip'):events.append({'action':event['Action'],'test':event['Test']})
required={'TestAcceptanceGroupLockOriginalDigestBindsAuthorityAndTTL','TestAcceptanceGroupLockLeaseTimeAndHistoricalReceipt','TestAcceptanceGroupLockClosedNativeBodiesRejectInventedAuthority','TestAcceptanceThreadOwnerProofSurvivesRealDeviceEncryptionAttacks','TestAcceptanceThreadAuthorityWitnessDetectsSameCountMutation','TestAcceptanceThreadSameSIDRejectsSecondHubBeforeRemoteAdmission','TestAcceptanceThreadLostJoinResponseFencesSecondHubAcrossRestart','TestAcceptanceGroupLocksActualHostOwnerLifecycle'}
missing=sorted(required-{e['test'] for e in events if e['action']=='pass'})
counts={key:sum(e['action']==key for e in events) for key in ('pass','fail','skip')}
stable=(root/'source-before.json').read_bytes()==(root/'source-after.json').read_bytes()
passed=status==0 and stable and not missing and not counts['fail'] and not counts['skip']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result={'schema':'cicada.thread-network-locks.acceptance.v1','status':'PASS' if passed else 'FAIL','exit_code':status if status else (0 if passed else 1),'process_exit_code':status,'source_head':(root/'source-head.txt').read_text().strip(),'source_dirty':bool((root/'git-status.txt').read_text().strip()),'source_stable':stable,'source_manifest_sha256':sha(root/'source-before.json'),'counts':counts,'missing_pass_tests':missing,'events':events,'not_run':['WINDOWS_DPAPI','WINDOWS_ACL','WINDOWS_GUI','PHYSICAL_NATIVE_RUNTIME','ANDROID','PUBLIC_DEPLOYMENT']}
(root/'result.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
artifacts={str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_relative_to(root/'go-build') and p.name!='artifact-sha256.json'}
(root/'artifact-sha256.json').write_text(json.dumps(artifacts,sort_keys=True,indent=2)+'\n')
print(result['status'], 'exit='+str(result['exit_code']),counts,'result_sha256='+sha(root/'result.json'))
raise SystemExit(result['exit_code'])
PY
