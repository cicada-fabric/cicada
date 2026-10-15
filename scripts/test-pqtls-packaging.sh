#!/usr/bin/env bash
# Actual relocated package / optional runtime image gate. No native/model calls.
set -Eeuo pipefail
umask 077
[[ $# -ge 4 && $# -le 5 ]] || { printf 'usage: %s PACKAGE_DIR ACCEPTED_PQ_STAGE NEW_EVIDENCE_DIR BUILD_RECEIPT [IMAGE_BUILD_RECEIPT]\nExpected receipt SHA256 values are required via CICADA_PQTLS_EXPECTED_RECEIPT_SHA256 and optional CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256.\n' "$0" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
producer_root="$(cd "${CICADA_PQTLS_PRODUCER_ROOT:-$repo_root}" && pwd -P)"
package="$(cd "$1" && pwd -P)"
pq_stage="$(cd "$2" && pwd -P)"
evidence="$(realpath -m "$3")"
receipt="$(realpath "$4")"
image_receipt="${5:-}"
[[ -n "${CICADA_PQTLS_EXPECTED_RECEIPT_SHA256:-}" ]] || { printf 'independently expected package receipt SHA required\n' >&2; exit 2; }
target_arch="$(python3 - "$package/BUILD-METADATA.json" <<'PY'
import json,sys
targets=json.load(open(sys.argv[1]))['targets']
if len(targets)!=1 or not targets[0].startswith('linux/'):raise SystemExit('package must declare one Linux target')
print(targets[0].split('/',1)[1])
PY
)"
[[ "$target_arch" == amd64 || "$target_arch" == arm64 ]] || { printf 'unsupported PQ package target\n' >&2; exit 2; }
identity_args=(--root "$producer_root" --package "$package" --pqtls-stage "$pq_stage" --receipt "$receipt" --receipt-sha256 "$CICADA_PQTLS_EXPECTED_RECEIPT_SHA256" --targetarch "$target_arch")
if [[ -n "$image_receipt" ]]; then
  image_receipt="$(realpath "$image_receipt")"
  [[ -n "${CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256:-}" ]] || { printf 'independently expected image receipt SHA required\n' >&2; exit 2; }
  identity_args+=(--image-receipt "$image_receipt" --image-receipt-sha256 "$CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256")
fi
[[ ! -e "$evidence" ]] || { printf 'gate evidence already exists\n' >&2; exit 2; }
mkdir -m 0700 -p "$evidence"
python3 "$producer_root/scripts/hub-build-input-inventory.py" verify-distribution "${identity_args[@]}" > "$evidence/identity-before.json"
python3 "$repo_root/scripts/hub-build-input-inventory.py" capture --transport pqtls --root "$repo_root" --pqtls-stage "$pq_stage" --targetarch "$target_arch" --output "$evidence/test-input-before.json"
root_inventory() {
  python3 - "$producer_root" "$repo_root" <<'PY'
import hashlib,json,os,stat,subprocess,sys
def inventory(root,role):
 paths=sorted(set(p for p in subprocess.check_output(['git','-C',root,'ls-files','-z','--cached','--others','--exclude-standard']).split(b'\0') if p))
 h=hashlib.sha256(b'cicada-pq-distribution-fixture-root-v1\0');count=0
 for rel in paths:
  path=os.fsencode(root)+b'/'+rel;info=os.lstat(path)
  if stat.S_ISREG(info.st_mode):
   with open(path,'rb') as f:data=f.read()
  elif stat.S_ISLNK(info.st_mode):data=os.readlink(path)
  else:raise SystemExit('unsupported source input type')
  after=os.lstat(path)
  if (info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise SystemExit('source changed during capture')
  h.update(len(rel).to_bytes(8,'big'));h.update(rel);h.update(stat.S_IMODE(info.st_mode).to_bytes(4,'big'));h.update(hashlib.sha256(data).digest());count+=1
 return {'root':root,'role':role,'head':subprocess.check_output(['git','-C',root,'rev-parse','HEAD'],text=True).strip(),'source_file_count':count,'root_source_sha256':h.hexdigest(),'domain':'cicada-pq-distribution-fixture-root-v1','scope':'cached and nonignored source paths; raw modes and content; excludes .git/ignored state'}
print(json.dumps({'producer':inventory(sys.argv[1],'immutable product producer'),'test_fixture':inventory(sys.argv[2],'changed test-only source, not product build')},sort_keys=True,indent=2))
PY
}
root_inventory > "$evidence/roots-before.json"
(cd "$package" && sha256sum --check --status SHA256SUMS)
image="$(python3 - "$evidence/identity-before.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['image_id'] or '')
PY
)"
git_common="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
producer_git_common="$(git -C "$producer_root" rev-parse --path-format=absolute --git-common-dir)"
module_cache="${CICADA_TEST_MODULE_CACHE:-$(dirname "$producer_git_common")/.cicada-data/m1-gomodcache}"
build_cache="${CICADA_TEST_BUILD_CACHE:-$evidence/go-build}"
[[ -d "$module_cache" ]] || { printf 'set CICADA_TEST_MODULE_CACHE to an existing offline module cache\n' >&2; exit 1; }
mkdir -p "$build_cache"
test_builder_image=golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61
if [[ "$target_arch" == arm64 ]]; then
  printf 'ARM64 package acceptance requires the isolated amd64-driver/explicit-QEMU Node gate; cmd TestPQDistribution remains amd64-only\n' >&2
  exit 2
fi
target_runner=''
target_cc=cc
package_binary=/artifact/bin/cicada
go_test_exec=()
fingerprint="$(python3 - "$package/BUILD-METADATA.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['source']['source_fingerprint'])
PY
)"
wasm_sha="$(python3 - "$package/BUILD-METADATA.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['hub_webcrypto_manifest_sha256'])
PY
)"
owner_token="$(python3 -c 'import secrets; print(secrets.token_hex(12))')"
driver="cicada-pqdist-driver-$owner_token"
hub="cicada-pqdist-hub-$owner_token"
driver_label="cicada.owner=driver-$owner_token"
hub_label="cicada.owner=hub-$owner_token"
request="$evidence/image-request.json"
# Fixed container-only synthetic names. Host DNS/hosts and artifacts stay unchanged.
fixture_hosts="$evidence/synthetic-hosts"
printf '127.0.0.1 localhost hub.synthetic.invalid\n::1 localhost\n' > "$fixture_hosts"
cleanup_fixture_roots() {
  python3 - "$evidence" <<'PY'
import json,pathlib,shutil,sys
root=pathlib.Path(sys.argv[1]).resolve();report=root/'fixture-cleanup.json';removed=json.loads(report.read_text())['removed_private_fixture_roots'] if report.exists() else []
for path in root.glob('synthetic-current-distribution-*'):
 if path.is_symlink() or not path.is_dir() or path.resolve().parent!=root:raise SystemExit('unsafe private fixture cleanup path')
 shutil.rmtree(path);removed.append(path.name)
remaining=[p.name for p in root.glob('synthetic-current-distribution-*')]
(root/'fixture-cleanup.json').write_text(json.dumps({'removed_private_fixture_roots':sorted(set(removed)),'remaining_private_fixture_roots':remaining,'test_container_temporary_node_state':'removed with own disposable driver container'},sort_keys=True)+'\n')
if remaining:raise SystemExit('private synthetic fixture remains')
PY
}
sanitize_evidence() {
  python3 - "$evidence" <<'PY'
import hashlib,json,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);gate=root/'gate.private.jsonl'
if gate.exists():
 events=[]
 for line in gate.read_text(errors='replace').splitlines():
  try:e=json.loads(line)
  except ValueError:e={'Action':'output','Output':line}
  text=e.get('Output','')
  if text:
   safe=text.strip()
   if not (safe.startswith(('=== RUN','--- PASS','--- FAIL','--- SKIP','PASS','FAIL','ok\t')) or re.fullmatch(r'[a-zA-Z0-9_.-]+\.go:\d+: phase=[a-zA-Z0-9_-]+',safe) or re.fullmatch(r'[a-zA-Z0-9_.-]+\.go:\d+: (?:shipped Hub|shipped Node Agent exit=0|idle shipped Node) transcript_sha256=[a-f0-9]{64} bytes=\d+',safe)):
    positions=re.findall(r'([a-zA-Z0-9_.-]+\.go:\d+:)',text)
    e['Output']='suppressed private diagnostics sha256='+hashlib.sha256(text.encode()).hexdigest()+' bytes='+str(len(text.encode()))+' public_codepoints='+','.join(positions)+'\n'
  events.append(e)
 (root/'gate.jsonl').write_text(''.join(json.dumps(e,sort_keys=True)+'\n' for e in events));gate.unlink()
log=root/'hub.private.log'
if log.exists():
 data=log.read_bytes();public=[line for line in data.decode(errors='replace').splitlines() if line.startswith(('Cicada Fabric listening on ','Cicada enrolled Node PQ TLS listening on '))]
 (root/'hub-transcript.json').write_text(json.dumps({'transcript_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'public_lifecycle':public},sort_keys=True)+'\n');log.unlink()
PY
}
cleanup_containers() {
  python3 - "$evidence" "$driver" "$hub" "$image" "$driver_label" "$hub_label" "$test_builder_image" <<'PY_CONTAINER'
import json,pathlib,re,subprocess,sys
root=pathlib.Path(sys.argv[1]);driver,hub,image,driver_label,hub_label,builder=sys.argv[2:]
def run(args):return subprocess.run(['docker',*args],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
def cleanup(name,label):
 cidfile=root/(name+'.cid');cid=cidfile.read_text().strip() if cidfile.exists() else ''
 if not re.fullmatch(r'[0-9a-f]{64}',cid):return {'name':name,'cid':None,'verified_absent':False,'reason':'exact container ID receipt missing'}
 detail=run(['inspect','--format','{{index .Config.Labels "cicada.owner"}}\t{{.Name}}\t{{.State.Running}}',cid])
 if detail.returncode==0:
  owner,found_name,running=detail.stdout.rstrip('\n').split('\t')
  if owner!=label.split('=',1)[1] or found_name.lstrip('/')!=name:raise SystemExit('refusing to operate on a container whose exact owner receipt does not match')
  if running=='true':run(['stop','--time','10',cid])
  run(['rm','--force',cid])
 check=run(['inspect','--format','{{.Id}}',cid])
 return {'name':name,'cid':cid,'owner_label':label,'inspect_exit':check.returncode,'verified_absent':check.returncode!=0}
entries=[cleanup(driver,driver_label)]
if image:entries.append(cleanup(hub,hub_label))
receipt={'containers':entries,'verified_absent':all(e['verified_absent'] for e in entries),
         'builder_image':builder,'runtime_image':image or None}
if (root/'gate.exit').exists():receipt['driver_process_exit']=int((root/'gate.exit').read_text())
if (root/'hub-runtime.json').exists():receipt['hub_process_exit']=json.loads((root/'hub-runtime.json').read_text())['exit']
(root/'container-cleanup.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
if not receipt['verified_absent']:raise SystemExit('owned disposable container absence not verified')
PY_CONTAINER
}
cleanup() {
  cleanup_containers || true
  sanitize_evidence || true
  cleanup_fixture_roots || true
}
trap cleanup EXIT INT TERM
env_args=()
if [[ -n "$image" ]]; then env_args+=(-e "PQTLS_TEST_IMAGE_REQUEST=$request"); fi
if [[ "${CICADA_PQTLS_OBSERVE_IDLE:-0}" == 1 ]]; then env_args+=(-e PQTLS_TEST_OBSERVE_IDLE=1); fi
driver_cid="$(docker create --name "$driver" --label "$driver_label" --cidfile "$evidence/$driver.cid" --platform linux/amd64 \
  --user "$(id -u):$(id -g)" --network none --cpus 2 --memory 3g --pids-limit 256 \
  -v "$repo_root:$repo_root:ro" -v "$git_common:$git_common:ro" -v "$producer_root:$producer_root:ro" \
  -v "$fixture_hosts:/etc/hosts:ro" \
  -v "$package:/artifact:ro" -v "$pq_stage:/pqtls-stage:ro" \
  -v "$evidence:$evidence" -v "$module_cache:/modcache:ro" -v "$build_cache:/gocache" \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off -e GOMODCACHE=/modcache -e GOCACHE=/gocache -e GOFLAGS=-buildvcs=false \
  -e CGO_ENABLED=1 -e "GOOS=linux" -e "GOARCH=$target_arch" -e "CC=$target_cc" -e "PQTLS_TEST_CC=$target_cc" \
  -e CGO_CFLAGS=-I/pqtls-stage/include -e CGO_LDFLAGS=-L/pqtls-stage/lib -e LD_LIBRARY_PATH=/pqtls-stage/lib \
  -e OPENSSL_CONF=/dev/null -e PQTLS_TEST_OPENSSL=/pqtls-stage/bin/openssl -e "PQTLS_TEST_ARTIFACT_DIR=$evidence" \
  -e "PQTLS_TEST_TARGET_RUNNER=$target_runner" -e "PQTLS_TEST_PACKAGE_BINARY=$package_binary" -e "PQTLS_TEST_EXPECTED_SOURCE_FINGERPRINT=$fingerprint" \
  -e "PQTLS_TEST_WEBCRYPTO_MANIFEST_SHA256=$wasm_sha" "${env_args[@]}" \
  -w "$repo_root/cicada-go" \
  "$test_builder_image" go test -tags cicada_pqtls -count=1 -json -timeout=12m "${go_test_exec[@]}" \
  -run '^TestPQDistributionActualHubNode$' ./cmd/cicada)"
[[ "$driver_cid" == "$(cat "$evidence/$driver.cid")" ]]
timeout --signal=TERM --kill-after=60s 900s docker start -a "$driver_cid" > "$evidence/gate.private.jsonl" 2>&1 &
driver_pid=$!
if [[ -n "$image" ]]; then
  for ((i=0;i<150;i++)); do
    [[ -f "$request" ]] && break
    kill -0 "$driver_pid" 2>/dev/null || break
    sleep 1
  done
  if [[ -f "$request" ]]; then
    readarray -t parameters < <(python3 - "$request" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for k in ('fixture_root','state_dir','config','port'):print(d[k])
PY
)
    hub_cid="$(docker create --name "$hub" --label "$hub_label" --cidfile "$evidence/$hub.cid" --network "container:$driver_cid" \
      --user "$(id -u):$(id -g)" --cpus 2 --memory 512m --pids-limit 128 \
      -v "${parameters[0]}:${parameters[0]}:ro" -v "${parameters[1]}:${parameters[1]}" -v "$fixture_hosts:/etc/hosts:ro" \
      -e "CICADA_STATE_DIR=${parameters[1]}" -e "CICADA_WORKSPACE_ROOT=${parameters[0]}/workspace" \
      "$image" serve --fabric-only --host 127.0.0.1 --port "${parameters[3]}" --node-pqtls-config "${parameters[2]}")"
    [[ "$hub_cid" == "$(cat "$evidence/$hub.cid")" ]]
    printf '%s\n' "$hub_cid" > "$evidence/hub-container-id.txt"
    docker start "$hub_cid" >/dev/null
    for ((i=0;i<210;i++)); do
      [[ -f "$request.done" ]] && break
      kill -0 "$driver_pid" 2>/dev/null || break
      if [[ -f "$request.memory-ready" && ! -f "$evidence/hub-idle-docker-stats.json" ]]; then
        docker stats --no-stream --format '{{json .}}' "$hub_cid" > "$evidence/hub-idle-docker-stats.json"
      fi
      sleep 1
    done
    docker cp "$hub_cid:/opt/cicada-pqtls/bin/cicada" "$evidence/image-binary.snapshot"
    sha256sum "$evidence/image-binary.snapshot" > "$evidence/image-binary.sha256"
    rm "$evidence/image-binary.snapshot"
    docker stop --time 10 "$hub_cid" > "$evidence/hub-stop.log"
    docker inspect --format '{{json .State.ExitCode}} {{json .Image}}' "$hub_cid" | python3 -c 'import json,sys;exit_code,image=json.loads("["+sys.stdin.read().strip().replace(" ",",",1)+"]");print(json.dumps({"exit":exit_code,"image":image},sort_keys=True))' > "$evidence/hub-runtime.json"
    docker logs "$hub_cid" > "$evidence/hub.private.log" 2>&1
    printf 'stopped\n' > "$request.stopped"
  fi
fi
set +e
wait "$driver_pid"
exit_code=$?
set -e
if [[ "$exit_code" == 124 || "$exit_code" == 137 ]]; then
  docker stop --time 10 "$driver_cid" > "$evidence/driver-timeout-stop.log"
fi
docker_exit="$(docker wait "$driver_cid")"
docker inspect --format '{{json .State}}' "$driver_cid" > "$evidence/driver-state.json"
if [[ "$exit_code" != 124 && "$exit_code" != 137 ]]; then [[ "$docker_exit" == "$exit_code" ]]; fi
printf '%s\n' "$exit_code" > "$evidence/gate.exit"
cleanup_containers
sanitize_evidence
cleanup_fixture_roots
python3 "$producer_root/scripts/hub-build-input-inventory.py" verify-distribution "${identity_args[@]}" > "$evidence/identity-after.json"
cmp "$evidence/identity-before.json" "$evidence/identity-after.json"
python3 "$repo_root/scripts/hub-build-input-inventory.py" capture --transport pqtls --root "$repo_root" --pqtls-stage "$pq_stage" --targetarch "$target_arch" --output "$evidence/test-input-after.json"
cmp "$evidence/test-input-before.json" "$evidence/test-input-after.json"
root_inventory > "$evidence/roots-after.json"
cmp "$evidence/roots-before.json" "$evidence/roots-after.json"
(cd "$package" && sha256sum --check --status SHA256SUMS)
python3 - "$evidence" "$image" "$target_arch" <<'PY'
import collections,hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);counts=collections.Counter();skips=[];target_arch=sys.argv[3]
for line in (root/'gate.jsonl').read_text().splitlines():
 try:event=json.loads(line)
 except ValueError:continue
 if event.get('Action') in ('pass','fail','skip'):
  test=event.get('Test');kind='sub' if test and '/' in test else 'top' if test else 'package'
  counts[event['Action']+'_'+kind]+=1
  if event['Action']=='skip':skips.append(event)
result={'process_exit':int((root/'gate.exit').read_text()),'counts':dict(counts),'skip_is_not_pass':True,'skips':skips,'runtime_image':sys.argv[2] or None,'test_builder_image':json.loads((root/'container-cleanup.json').read_text())['builder_image'],'target_platform':'linux/'+target_arch,'target_execution':'user-mode-qemu' if target_arch=='arm64' else 'native-amd64','topology':'one Hub/two independent real Node Agent processes; image gate shares an isolated test namespace; not independent PQ Hubs/native/public proof','no_model_provider_native_calls':True}
if counts['pass_top']!=1 or counts['pass_sub']!=4 or any(v for k,v in counts.items() if k.startswith(('fail_','skip_'))):result['process_exit']=1
identity=json.loads((root/'identity-before.json').read_text());test_input=json.loads((root/'test-input-before.json').read_text());roots=json.loads((root/'roots-before.json').read_text())
result['producer_source']=roots['producer'];result['test_fixture_source']=roots['test_fixture']
result['product_input_source_fingerprint']=identity['source_fingerprint'];result['test_input_source_fingerprint']=test_input['fingerprint']['sha256']
result['package_file_sha256']=identity['package_file_sha256'];result['product_source_unchanged']=True;result['test_source_unchanged']=True
result['container_cleanup']=json.loads((root/'container-cleanup.json').read_text())
if not result['container_cleanup']['verified_absent']:result['process_exit']=1
result['private_fixture_cleanup']=json.loads((root/'fixture-cleanup.json').read_text())
if result['private_fixture_cleanup']['remaining_private_fixture_roots']:result['process_exit']=1
if (root/'image-binary.sha256').exists():result['image_binary_sha256']=(root/'image-binary.sha256').read_text().split()[0]
if (root/'hub-runtime.json').exists():
 runtime=json.loads((root/'hub-runtime.json').read_text());result['hub_exit']=runtime['exit'];result['image_id']=runtime['image']
 if result['hub_exit']!=0:result['process_exit']=1
result['evidence_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
(root/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','image_labels','skips')},sort_keys=True))
raise SystemExit(result['process_exit'])
PY
exit "$exit_code"
