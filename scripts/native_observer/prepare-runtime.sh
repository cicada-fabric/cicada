#!/bin/bash
# Default-off, owned CLI image preparation only. Never starts a Native session.
set -euo pipefail
umask 077
if [[ $# == 0 ]]; then
  printf '%s\n' '{"status":"NONAUTH","effects":false,"model_calls":0}'
  exit 0
fi
mode=${1-}
[[ $mode == --prepare ]] || { printf '%s\n' 'BLOCKED_ARGUMENTS'; exit 2; }
shift
result_dir= unique_run=
while [[ $# -gt 0 ]]; do
  case "$1" in
    --result-dir) [[ $# -ge 2 ]] || exit 2; result_dir=$2; shift 2;;
    --unique-run) [[ $# -ge 2 ]] || exit 2; unique_run=$2; shift 2;;
    *) printf '%s\n' 'BLOCKED_ARGUMENTS'; exit 2;;
  esac
done
[[ $unique_run =~ ^cicada-runtime-161-[a-z0-9]{8,32}$ ]] || exit 2
artifact_parent=/home/zyf/CICADA/.cicada-data/native-observer-runtime-161-20261007
[[ $result_dir == "$artifact_parent/$unique_run" && ! -e $result_dir ]] || exit 2
binary=/home/zyf/.codex/packages/standalone/releases/0.161.0-x86_64-unknown-linux-musl/bin/codex
binary_sha=9a820c17865fa825d04db416818679a9d63bd72e50835c396f496e5684626c9c
companion=${binary%/*}/codex-code-mode-host
companion_sha=e87096087c02aa6ab90a5a85031659665aa0bf3ee20c07ca0b8ab701c83fcd5b
bwrap=${binary%/bin/codex}/codex-resources/bwrap
bwrap_sha=77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c
bwrap_license=/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/official-codex-0161-bwrap-COPYING-20261007b.txt
bwrap_license_sha=b7993225104d90ddd8024fd838faf300bea5e83d91203eab98e29512acebd69c
bwrap_source_sha=eeb85b29dd6d89526ba6887ee2eab769675952a5f526ada1b26bb929f5133ec6
bwrap_source_bytes=99
bwrap_provenance=/home/zyf/CICADA/.cicada-data/native-observer-wiring-20261007/official-bwrap-0161-verification-20261007b.NONAUTH.json
[[ -f $bwrap && ! -L $bwrap && -f $bwrap_license && ! -L $bwrap_license && -f $bwrap_provenance && ! -L $bwrap_provenance ]] || exit 2
[[ $(stat -c '%s:%a' "$bwrap") == 529776:755 ]] || exit 2
[[ $(sha256sum "$bwrap" | cut -d' ' -f1) == "$bwrap_sha" ]] || exit 2
[[ $(stat -c '%s' "$bwrap_license") == 25383 ]] || exit 2
[[ $(sha256sum "$bwrap_license" | cut -d' ' -f1) == "$bwrap_license_sha" ]] || exit 2
bwrap_provenance_sha=$(sha256sum "$bwrap_provenance" | cut -d' ' -f1)
python3 - "$bwrap_provenance" <<'PYRESOURCE'
import json,sys
r=json.load(open(sys.argv[1]));assert r['status']=='PASS' and r['host_artifact_equal'] is True
assert r['release_commit']=='979011409de0a60b52f179721948e65531d26144'
assert r['archive']=={'bytes':261563,'sha256':'68f3b912c9d5f113343f6e054b5bb2be3cbbc09d21fcbc67ea6e997ed4b1cbfd','url':'https://github.com/openai/codex/releases/download/rust-v0.161.0/bwrap-x86_64-unknown-linux-musl.tar.gz'}
assert r['member']=={'bytes':529776,'mode':'0o755','name':'bwrap-x86_64-unknown-linux-musl','sha256':'77360cb751ccedc5971391444ac86a8a33c15b04d6b4a6fe45f5d25496e62c4c'}
assert r['license_file_sha256']=='b7993225104d90ddd8024fd838faf300bea5e83d91203eab98e29512acebd69c'
PYRESOURCE
base=sha256:d6004eb3f669966f7a30796333b8a4b1635b30ded40cc7d186e19c42c196818f
[[ $(stat -c '%s:%a' "$binary") == 292309256:755 ]] || exit 2
[[ $(sha256sum "$binary" | cut -d' ' -f1) == "$binary_sha" ]] || exit 2
[[ $(stat -c '%s:%a' "$companion") == 74068880:755 ]] || exit 2
[[ $(sha256sum "$companion" | cut -d' ' -f1) == "$companion_sha" ]] || exit 2
mkdir -p -m 700 "$artifact_parent"
mkdir -m 700 "$result_dir"
mkdir -m 700 "$result_dir/context" "$result_dir/docker-config"
export DOCKER_CONFIG="$result_dir/docker-config"
export DOCKER_BUILDKIT=0
script_path=$(readlink -f "${BASH_SOURCE[0]}")
script_before=$(sha256sum "$script_path" | cut -d' ' -f1)
check_name="$unique_run-check"
image_tag="cicada/native-observer-runtime-161:$unique_run"
image_id= container_id= submitted=false check_pass=false cleanup_proven=false check_name_absent=false

inspect_owned() {
  timeout --kill-after=2s 5s docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"run":{{json (index .Config.Labels "org.cicada.test.run")}},"fixture":{{json (index .Config.Labels "org.cicada.test.fixture")}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},"exit_code":{{json .State.ExitCode}},"network":{{json .HostConfig.NetworkMode}}}' "$1"
}
cleanup() {
  original_exit=$?
  trap - EXIT
  if [[ $submitted == true && $check_name_absent == true ]]; then
    set +e
    # Each Docker observation/action is bounded; only exact owned identity permits stop/rm.
    timeout --kill-after=2s 5s docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"run":{{json (index .Config.Labels "org.cicada.test.run")}},"fixture":{{json (index .Config.Labels "org.cicada.test.fixture")}},"status":{{json .State.Status}},"pid":{{json .State.Pid}},"exit_code":{{json .State.ExitCode}},"network":{{json .HostConfig.NetworkMode}}}' "${container_id:-$check_name}" >"$result_dir/cleanup-identity.json" 2>"$result_dir/cleanup-inspect.stderr"
    inspect_exit=$?
    if [[ $inspect_exit == 0 ]] && python3 - "$result_dir/cleanup-identity.json" "$check_name" "$image_id" "$unique_run" <<'PY'
import json,sys,re
try:
 r=json.load(open(sys.argv[1])); assert re.fullmatch('[0-9a-f]{64}',r['id'])
 assert r['name']=='/'+sys.argv[2] and r['image']==sys.argv[3] and r['run']==sys.argv[4] and r['fixture']=='native-observer-cli161'
except Exception: sys.exit(1)
PY
    then
      container_id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$result_dir/cleanup-identity.json")
      timeout --kill-after=2s 8s docker stop --time 1 "$container_id" >"$result_dir/stop.stdout" 2>"$result_dir/stop.stderr"
      printf '%s\n' "$?" >"$result_dir/stop.exit"
      timeout --kill-after=2s 5s docker rm "$container_id" >"$result_dir/rm.stdout" 2>"$result_dir/rm.stderr"
      printf '%s\n' "$?" >"$result_dir/rm.exit"
      timeout --kill-after=2s 5s docker inspect --format '{{.Id}}' "$container_id" >"$result_dir/absence.stdout" 2>"$result_dir/absence.stderr"
      absence_exit=$?
      if [[ $absence_exit == 1 ]] && [[ -z $(tr -d '[:space:]' <"$result_dir/absence.stdout") ]] && [[ $(cat "$result_dir/absence.stderr") == "Error: No such object: $container_id" || $(cat "$result_dir/absence.stderr") == "error: no such object: $container_id" ]]; then cleanup_proven=true; fi
    fi
    set -e
  fi
  python3 - "$result_dir" "$image_id" "$container_id" "$unique_run" "$check_pass" "$cleanup_proven" "$original_exit" "$binary_sha" "$script_before" "$script_path" "$companion_sha" "$bwrap_provenance" "$bwrap_provenance_sha" <<'PY'
import json,os,sys,hashlib
from pathlib import Path
p=Path(sys.argv[1]); records={}
for f in p.iterdir():
 if f.is_file():
  b=f.read_bytes();s=f.stat();records[f.name]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'rawmode':oct(s.st_mode)}
script_after=hashlib.sha256(Path(sys.argv[10]).read_bytes()).hexdigest()
ok=script_after==sys.argv[9] and sys.argv[5]=='true' and sys.argv[6]=='true' and sys.argv[7]=='0'
r={'authority':'NONAUTH_ZERO_MODEL','status':'CLI_IMAGE_CHECK_PASS_NATIVE_PREPARATION_NOT_RUN' if ok else 'FAIL_OR_UNKNOWN','image_id':sys.argv[2],'container_id':sys.argv[3] or None,'run_label':sys.argv[4],'fixture_label':'native-observer-cli161','check_pass':sys.argv[5]=='true','owned_container_absent':sys.argv[6]=='true','retained_image_artifact':bool(sys.argv[2]),'primary_exit':int(sys.argv[7]),'effective_exit':0 if ok else 1,'CLI_sha256':sys.argv[8],'companion_sha256':sys.argv[11],'companion_execution':'NOT_RUN_HASH_ONLY','CLI_checks':1 if (p/'check.stdout').exists() else 0,'Runtime_sessions':0,'model_calls':0,'provider_POSTs':0,'credential_access':False,'protocol_observer_G1_readiness':'NOT_RUN','script_sha256_before':sys.argv[9],'script_sha256_after':hashlib.sha256(Path(sys.argv[10]).read_bytes()).hexdigest(),'script_unchanged':hashlib.sha256(Path(sys.argv[10]).read_bytes()).hexdigest()==sys.argv[9],'files':records}
resource=json.loads(Path(sys.argv[12]).read_bytes())
r['bwrap']={'release_commit':resource['release_commit'],'CODEX_RELEASE_SOURCE':'https://github.com/openai/codex/tree/979011409de0a60b52f179721948e65531d26144','upstream_source_completeness':'NOT_PROVEN','archive':resource['archive'],'member':resource['member'],
 'installed_path':'/home/cicada/.local/bin/codex-resources/bwrap','execution':'NOT_RUN_HASH_ONLY',
 'license_sha256':resource['license_file_sha256'],'license_bytes':25383,'license_installed_path':'/home/cicada/.local/bin/codex-resources/bwrap.COPYING',
 'source_file':{'installed_path':'/home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt','sha256':'eeb85b29dd6d89526ba6887ee2eab769675952a5f526ada1b26bb929f5133ec6','bytes':99,'mode':'0o644'},'license_mode':'0o644','provenance_sha256_before':sys.argv[13],'provenance_sha256_after':hashlib.sha256(Path(sys.argv[12]).read_bytes()).hexdigest()}
r['bwrap']['context_copies']={}
for name in ('bwrap','bwrap.COPYING','bwrap.SOURCE.txt'):
 f=p/'context'/'codex-resources'/name
 if f.is_file() and not f.is_symlink():
  raw=f.read_bytes();metadata=f.stat();r['bwrap']['context_copies'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'rawmode':oct(metadata.st_mode)}
f=os.open(p/'result.NONAUTH.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(f,'w') as out: json.dump(r,out,sort_keys=True,indent=2);out.write('\n')
PY
  [[ $original_exit == 0 && $cleanup_proven == true ]] || exit 1
}
trap cleanup EXIT
timeout --kill-after=2s 5s docker image inspect --format '{{.Id}}' "$base" >"$result_dir/base-image.stdout" 2>"$result_dir/base-image.stderr"
[[ $(cat "$result_dir/base-image.stdout") == "$base" ]]
cp "$binary" "$result_dir/context/codex"
cp "$companion" "$result_dir/context/codex-code-mode-host"
[[ $(sha256sum "$result_dir/context/codex-code-mode-host" | cut -d' ' -f1) == "$companion_sha" ]]
[[ $(sha256sum "$result_dir/context/codex" | cut -d' ' -f1) == "$binary_sha" ]]
mkdir -m 700 "$result_dir/context/codex-resources"
cp "$bwrap" "$result_dir/context/codex-resources/bwrap"
cp "$bwrap_license" "$result_dir/context/codex-resources/bwrap.COPYING"
printf '%s\n' 'CODEX_RELEASE_SOURCE=https://github.com/openai/codex/tree/979011409de0a60b52f179721948e65531d26144' >"$result_dir/context/codex-resources/bwrap.SOURCE.txt"
chmod 0644 "$result_dir/context/codex-resources/bwrap.SOURCE.txt"
[[ $(stat -c '%s:%a' "$result_dir/context/codex-resources/bwrap.SOURCE.txt") == "$bwrap_source_bytes:644" ]]
[[ $(sha256sum "$result_dir/context/codex-resources/bwrap.SOURCE.txt" | cut -d' ' -f1) == "$bwrap_source_sha" ]]
chmod 0755 "$result_dir/context/codex-resources/bwrap"
chmod 0644 "$result_dir/context/codex-resources/bwrap.COPYING"
[[ $(sha256sum "$result_dir/context/codex-resources/bwrap" | cut -d' ' -f1) == "$bwrap_sha" ]]
[[ $(sha256sum "$result_dir/context/codex-resources/bwrap.COPYING" | cut -d' ' -f1) == "$bwrap_license_sha" ]]
cat >"$result_dir/context/Dockerfile" <<EOF
FROM $base
USER 0:0
COPY codex /tmp/codex-install
COPY codex-code-mode-host /tmp/companion-install
COPY codex-resources /tmp/codex-resources-install
RUN test "\$(sha256sum /tmp/codex-install | cut -d' ' -f1)" = "$binary_sha" && rm -f /home/cicada/.local/bin/codex && install -m 0755 -o 1000 -g 1000 /tmp/codex-install /home/cicada/.local/bin/codex && test "\$(sha256sum /tmp/companion-install | cut -d' ' -f1)" = "$companion_sha" && rm -f /home/cicada/.local/bin/codex-code-mode-host && install -m 0755 -o 1000 -g 1000 /tmp/companion-install /home/cicada/.local/bin/codex-code-mode-host && rm /tmp/codex-install /tmp/companion-install
RUN test "\$(sha256sum /tmp/codex-resources-install/bwrap | cut -d' ' -f1)" = "$bwrap_sha" && test "\$(sha256sum /tmp/codex-resources-install/bwrap.COPYING | cut -d' ' -f1)" = "$bwrap_license_sha" && test "\$(sha256sum /tmp/codex-resources-install/bwrap.SOURCE.txt | cut -d' ' -f1)" = "$bwrap_source_sha" && install -d -m 0755 -o 1000 -g 1000 /home/cicada/.local/bin/codex-resources && install -m 0755 -o 1000 -g 1000 /tmp/codex-resources-install/bwrap /home/cicada/.local/bin/codex-resources/bwrap && install -m 0644 -o 1000 -g 1000 /tmp/codex-resources-install/bwrap.COPYING /home/cicada/.local/bin/codex-resources/bwrap.COPYING && install -m 0644 -o 1000 -g 1000 /tmp/codex-resources-install/bwrap.SOURCE.txt /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt && rm -r /tmp/codex-resources-install
LABEL org.cicada.test.run="$unique_run" org.cicada.test.fixture="native-observer-cli161" org.cicada.test.cli.sha256="$binary_sha"
USER 1000:1000
ENV PATH=/home/cicada/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF
timeout --kill-after=10s 120s docker build --pull=false --network=none --rm --force-rm --iidfile "$result_dir/image-id" -t "$image_tag" "$result_dir/context" >"$result_dir/build.stdout" 2>"$result_dir/build.stderr"
image_id=$(cat "$result_dir/image-id")
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]]
timeout --kill-after=2s 5s docker image inspect --format '{"id":{{json .Id}},"run":{{json (index .Config.Labels "org.cicada.test.run")}},"fixture":{{json (index .Config.Labels "org.cicada.test.fixture")}},"CLI_sha256":{{json (index .Config.Labels "org.cicada.test.cli.sha256")}}}' "$image_id" >"$result_dir/image-public.json"
image_run=$unique_run
python3 - "$result_dir/image-public.json" "$image_id" "$binary_sha" "$image_run" <<'PYIMAGE'
import json,sys
r=json.load(open(sys.argv[1]));assert r['id']==sys.argv[2] and r['CLI_sha256']==sys.argv[3] and r['fixture']=='native-observer-cli161' and r['run']==sys.argv[4]
PYIMAGE
set +e
 timeout --kill-after=2s 5s docker inspect --format '{{.Id}}' "$check_name" >"$result_dir/name-before.stdout" 2>"$result_dir/name-before.stderr"
 name_exit=$?
set -e
[[ $name_exit == 1 && -z $(tr -d '[:space:]' <"$result_dir/name-before.stdout") ]]
[[ $(cat "$result_dir/name-before.stderr") == "Error: No such object: $check_name" || $(cat "$result_dir/name-before.stderr") == "error: no such object: $check_name" ]]
check_name_absent=true
submitted=true
check_program='test -d "$CODEX_HOME"; printf "%s\n" "$PATH"; command -v codex; sha256sum "$(command -v codex)"; codex --version; command -v codex-code-mode-host; sha256sum "$(command -v codex-code-mode-host)"; test -f /home/cicada/.local/bin/codex-resources/bwrap; test ! -L /home/cicada/.local/bin/codex-resources/bwrap; test "$(stat -c %s:%a /home/cicada/.local/bin/codex-resources/bwrap)" = 529776:755; test -f /home/cicada/.local/bin/codex-resources/bwrap.COPYING; test ! -L /home/cicada/.local/bin/codex-resources/bwrap.COPYING; test "$(stat -c %s:%a /home/cicada/.local/bin/codex-resources/bwrap.COPYING)" = 25383:644; test -f /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt; test ! -L /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt; test "$(stat -c %s:%a /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt)" = 99:644; sha256sum /home/cicada/.local/bin/codex-resources/bwrap /home/cicada/.local/bin/codex-resources/bwrap.COPYING /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt'
printf '%s\n' '/bin/sh -eu -c' "$check_program" >"$result_dir/check-command.txt"
container_id=$(timeout --kill-after=2s 10s docker create --name "$check_name" --label "org.cicada.test.run=$unique_run" --label org.cicada.test.fixture=native-observer-cli161 --network none --read-only --user 1000:1000 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,uid=1000,gid=1000 --tmpfs /home/cicada/.codex-version-check:rw,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000 -e CODEX_HOME=/home/cicada/.codex-version-check --entrypoint /bin/sh "$image_id" -eu -c "$check_program" 2>"$result_dir/create.stderr")
printf '%s\n' "$container_id" >"$result_dir/container-id"
[[ $container_id =~ ^[0-9a-f]{64}$ ]] || { container_id=; exit 1; }
inspect_owned "$container_id" >"$result_dir/created-identity.json"
python3 - "$result_dir/created-identity.json" "$container_id" "$check_name" "$image_id" "$unique_run" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['id']==sys.argv[2] and r['name']=='/'+sys.argv[3] and r['image']==sys.argv[4]
assert r['run']==sys.argv[5] and r['fixture']=='native-observer-cli161' and r['network']=='none' and r['status']=='created' and r['pid']==0
PY
timeout --kill-after=2s 20s docker start -a "$container_id" >"$result_dir/check.stdout" 2>"$result_dir/check.stderr"
printf '%s\n' '/home/cicada/.local/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' '/home/cicada/.local/bin/codex' "$binary_sha  /home/cicada/.local/bin/codex" 'codex-cli 0.161.0' '/home/cicada/.local/bin/codex-code-mode-host' "$companion_sha  /home/cicada/.local/bin/codex-code-mode-host" "$bwrap_sha  /home/cicada/.local/bin/codex-resources/bwrap" "$bwrap_license_sha  /home/cicada/.local/bin/codex-resources/bwrap.COPYING" "$bwrap_source_sha  /home/cicada/.local/bin/codex-resources/bwrap.SOURCE.txt" >"$result_dir/expected.stdout"
cmp -s "$result_dir/check.stdout" "$result_dir/expected.stdout"
[[ ! -s $result_dir/check.stderr ]]
inspect_owned "$container_id" >"$result_dir/terminal-identity.json"
python3 - "$result_dir/terminal-identity.json" "$container_id" "$unique_run" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]));assert r['id']==sys.argv[2] and r['run']==sys.argv[3] and r['network']=='none'
assert r['status']=='exited' and r['exit_code']==0 and type(r['pid']) is int and r['pid']==0
PY
check_pass=true

[[ $(sha256sum "$binary" | cut -d' ' -f1) == "$binary_sha" ]]
[[ $(sha256sum "$companion" | cut -d' ' -f1) == "$companion_sha" ]]
[[ -f $bwrap && ! -L $bwrap && -f $bwrap_license && ! -L $bwrap_license && -f $bwrap_provenance && ! -L $bwrap_provenance ]]
[[ $(stat -c '%s:%a' "$bwrap") == 529776:755 ]]
[[ $(sha256sum "$bwrap" | cut -d' ' -f1) == "$bwrap_sha" ]]
[[ $(sha256sum "$bwrap_license" | cut -d' ' -f1) == "$bwrap_license_sha" ]]
[[ $(sha256sum "$bwrap_provenance" | cut -d' ' -f1) == "$bwrap_provenance_sha" ]]
