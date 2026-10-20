#!/usr/bin/env bash
# Build acceptance-only Windows tests. A cross-build never accepts Windows runtime.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
local_root="${CICADA_N2_WINDOWS_LOCAL_ROOT:-$(dirname "$(dirname "$common_dir")")/.local}"
module_cache="${CICADA_N2_GOMODCACHE:-$local_root/cache/n2-acceptance/gomod-go1.27.2-stable}"
build_cache="${CICADA_N2_WINDOWS_GOCACHE:-$local_root/cache/n2-acceptance/native-windows-go-build-go1.27.3}"
image='golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110'
if [[ "$#" -ne 0 ]]; then printf 'Usage: scripts/build-native-app-n2-windows.sh\n' >&2; exit 2; fi
if [[ ! -d "$module_cache" ]] || ! docker image inspect "$image" >/dev/null 2>&1; then
 printf 'Pinned Go image and populated read-only offline module cache are required.\n' >&2; exit 2
fi
mkdir -p "$local_root/evidence/n2-acceptance" "$local_root/artifacts/n2-acceptance" "$local_root/state/n2-acceptance" "$build_cache"
exec 9>"$build_cache/driver.lock"
flock -n 9 || { printf 'Native Windows build cache is in use.\n' >&2; exit 2; }
evidence="$(mktemp -d "$local_root/evidence/n2-acceptance/windows-build-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
run_id="$(basename "$evidence")"
artifact="$local_root/artifacts/n2-acceptance/$run_id"
state="$local_root/state/n2-acceptance/$run_id"
mkdir "$artifact" "$state" "$state/tmp"
container="cicada-n2-native-${run_id,,}"
cleanup() {
 if [[ "$(docker inspect --format '{{index .Config.Labels "cicada.n2.native.run"}}' "$container" 2>/dev/null || true)" == "$run_id" ]]; then
  docker rm -f "$container" >/dev/null 2>&1 || true
 fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
snapshot() {
 python3 - "$repo_root" "$1" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
repo,dest=map(Path,sys.argv[1:])
paths=[p for p in (repo/'cicada-go').rglob('*') if p.is_file()]
paths.extend(p for p in (repo/'scripts').glob('*native*app*n2*windows*') if p.is_file())
files={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
manifest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
dest.write_text(json.dumps({'head':subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),
 'dirty':bool(subprocess.check_output(['git','-C',str(repo),'status','--porcelain','--untracked-files=all'])),
 'manifest_sha256':manifest,'files':files},indent=2,sort_keys=True)+'\n')
PY
}
snapshot "$evidence/source-before.json"
common=(docker run --rm --name "$container" --label "cicada.n2.native.run=$run_id"
 --network none --read-only --cap-drop ALL --security-opt no-new-privileges
 --cpus=3 --memory=3g --pids-limit=256 --user "$(id -u):$(id -g)"
 --tmpfs /tmp:rw,nosuid,nodev,size=1g
 -e GOMAXPROCS=2 -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off
 -e GOMODCACHE=/gomodcache -e GOCACHE=/gocache -e TMPDIR=/state/tmp
 --mount "type=bind,src=$repo_root,dst=/repo,readonly"
 --mount "type=bind,src=$module_cache,dst=/gomodcache,readonly"
 --mount "type=bind,src=$build_cache,dst=/gocache"
 --mount "type=bind,src=$artifact,dst=/out"
 --mount "type=bind,src=$state,dst=/state"
 --workdir /repo/cicada-go "$image")
lane() {
 local name="$1"; shift
 set +e
 "${common[@]}" "$@" >"$evidence/$name.log" 2>&1
 local code="$?"
 set -e
 printf '%s\n' "$code" >"$evidence/$name.exit"
 printf 'Native Windows %s exit=%s\n' "$name" "$code"
}
lane version go version
lane linux-vault go test -json -mod=readonly -p=1 -count=1 -timeout=90s ./internal/appvault
lane windows-vet env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go vet -mod=readonly ./internal/appvault
lane windows-compile env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -mod=readonly -trimpath -c -o /out/cicada-appvault-tests.exe ./internal/appvault
snapshot "$evidence/source-after.json"
cleanup
python3 - "$repo_root" "$evidence" "$artifact" "$image" <<'PY'
import hashlib,json,shutil,subprocess,sys,zipfile
from pathlib import Path
repo,evidence,artifact=map(Path,sys.argv[1:4]);image=sys.argv[4]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
before=json.loads((evidence/'source-before.json').read_text());after=json.loads((evidence/'source-after.json').read_text())
codes={p.stem:int(p.read_text()) for p in evidence.glob('*.exit')}
events=[]
for line in (evidence/'linux-vault.log').read_text(errors='replace').splitlines():
 try:r=json.loads(line)
 except ValueError:continue
 if r.get('Action') in ('pass','fail','skip') and 'Test' in r:events.append((r['Test'],r['Action']))
expected={'TestVaultEncryptsKeysPersistsStateAndChecksFullScope','TestVaultRejectsConcurrentWriter',
 'TestVaultFencesPostCommitFailureUntilReopen','TestVaultDoesNotRepairExistingBroadDirectoryPermissions',
 'TestDiscoveryRejectsLinksPermissionsAndOversize','TestDiscoveryDoesNotInitializeMissingDirectory'}
missing=sorted(expected-{name for name,action in events if action=='pass'})
passed=set(codes)=={'version','linux-vault','windows-vet','windows-compile'} and not any(codes.values()) and before==after and not missing and not any(action in ('fail','skip') for _,action in events)
result={'schema':'cicada.n2.windows.native-build-validation.v1','build_status':'PASS' if passed else 'FAIL',
 'exit_code':0 if passed else 1,'exit_codes':codes,'source_head':before['head'],'source_dirty':before['dirty'],
 'source_manifest_sha256':before['manifest_sha256'],'source_stable':before==after,'builder_image':image,
 'linux_test_events':{a:sum(action==a for _,action in events) for a in ('pass','fail','skip')},'missing_tests':missing,
 'windows_native_execution':'NOT_RUN','cross_user_dpapi':'NOT_RUN','native_acl':'NOT_RUN'}
if passed:
 for name in ('run-native-app-n2-windows.ps1','native_app_n2_windows_evidence.py'):
  shutil.copyfile(repo/'scripts'/name,artifact/name)
 files={p.name:sha(p) for p in artifact.iterdir() if p.is_file()}
 build={'schema':'cicada.n2.windows.native-build.v1','source_head':before['head'],'source_dirty':before['dirty'],
  'source_manifest_sha256':before['manifest_sha256'],'builder_image':image,'go_version':(evidence/'version.log').read_text().strip(),
  'target':'windows/amd64','cgo_enabled':False,'files':files,'native_execution':'NOT_RUN',
  'test_source_sha256':sha(repo/'cicada-go/internal/appvault/n2_native_windows_test.go')}
 (artifact/'n2-native-windows-build.json').write_text(json.dumps(build,indent=2,sort_keys=True)+'\n')
 (artifact/'SHA256SUMS').write_text(''.join(f'{sha(p)}  {p.name}\n' for p in sorted(artifact.iterdir()) if p.is_file()))
 bundle=artifact.parent/(artifact.name+'.zip')
 with zipfile.ZipFile(bundle,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for p in sorted(artifact.iterdir()):
   if p.is_file():z.write(p,p.name)
 result['artifact_directory']=str(artifact);result['build_manifest_sha256']=sha(artifact/'n2-native-windows-build.json')
 result['bundle_zip']=str(bundle);result['bundle_zip_sha256']=sha(bundle)
 (evidence/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
else:
 (evidence/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
index={p.name:sha(p) for p in sorted(evidence.iterdir()) if p.is_file()}
(evidence/'artifacts.sha256.json').write_text(json.dumps(index,indent=2,sort_keys=True)+'\n')
print('Native Windows build evidence:',evidence);print('Native Windows bundle:',artifact);print('Actual Windows execution: NOT_RUN')
sys.exit(result['exit_code'])
PY
