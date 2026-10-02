#!/usr/bin/env bash
# Actual relocated package / optional runtime image gate. No native/model calls.
set -Eeuo pipefail
umask 077
[[ $# -ge 4 && $# -le 5 ]] || { printf 'usage: %s PACKAGE_DIR ACCEPTED_PQ_STAGE NEW_EVIDENCE_DIR BUILD_RECEIPT [IMAGE_BUILD_RECEIPT]\nExpected receipt SHA256 values are required via CICADA_PQTLS_EXPECTED_RECEIPT_SHA256 and optional CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256.\n' "$0" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
package="$(cd "$1" && pwd -P)"
pq_stage="$(cd "$2" && pwd -P)"
evidence="$(realpath -m "$3")"
receipt="$(realpath "$4")"
image_receipt="${5:-}"
[[ -n "${CICADA_PQTLS_EXPECTED_RECEIPT_SHA256:-}" ]] || { printf 'independently expected package receipt SHA required\n' >&2; exit 2; }
identity_args=(--root "$repo_root" --package "$package" --pqtls-stage "$pq_stage" --receipt "$receipt" --receipt-sha256 "$CICADA_PQTLS_EXPECTED_RECEIPT_SHA256")
if [[ -n "$image_receipt" ]]; then
  image_receipt="$(realpath "$image_receipt")"
  [[ -n "${CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256:-}" ]] || { printf 'independently expected image receipt SHA required\n' >&2; exit 2; }
  identity_args+=(--image-receipt "$image_receipt" --image-receipt-sha256 "$CICADA_PQTLS_EXPECTED_IMAGE_RECEIPT_SHA256")
fi
[[ ! -e "$evidence" ]] || { printf 'gate evidence already exists\n' >&2; exit 2; }
mkdir -m 0700 -p "$evidence"
python3 "$repo_root/scripts/hub-build-input-inventory.py" verify-distribution "${identity_args[@]}" > "$evidence/identity-before.json"
(cd "$package" && sha256sum --check --status SHA256SUMS)
image="$(python3 - "$evidence/identity-before.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['image_id'] or '')
PY
)"
git_common="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
module_cache="${CICADA_TEST_MODULE_CACHE:-$(dirname "$git_common")/.cicada-data/m1-gomodcache}"
build_cache="${CICADA_TEST_BUILD_CACHE:-$evidence/go-build}"
[[ -d "$module_cache" ]] || { printf 'set CICADA_TEST_MODULE_CACHE to an existing offline module cache\n' >&2; exit 1; }
mkdir -p "$build_cache"
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
driver="cicada-pqdist-driver-$$"
hub="cicada-pqdist-hub-$$"
request="$evidence/image-request.json"
hub_started=false
cleanup() {
  if [[ "$hub_started" == true ]]; then docker stop --time 10 "$hub" >/dev/null 2>&1 || true; docker rm "$hub" >/dev/null 2>&1 || true; fi
  docker rm --force "$driver" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
env_args=()
if [[ -n "$image" ]]; then env_args+=(-e "PQTLS_TEST_IMAGE_REQUEST=$request"); fi
if [[ "${CICADA_PQTLS_OBSERVE_IDLE:-0}" == 1 ]]; then env_args+=(-e PQTLS_TEST_OBSERVE_IDLE=1); fi
docker run --rm --name "$driver" --user "$(id -u):$(id -g)" --network none --cpus 4 --memory 3g --pids-limit 512 \
  -v "$repo_root:$repo_root:ro" -v "$git_common:$git_common:ro" \
  -v "$package:/artifact:ro" -v "$pq_stage:/pqtls-stage:ro" \
  -v "$evidence:$evidence" -v "$module_cache:/modcache:ro" -v "$build_cache:/gocache" \
  -e GOTOOLCHAIN=local -e GOPROXY=off -e GOSUMDB=off -e GOMODCACHE=/modcache -e GOCACHE=/gocache -e GOFLAGS=-buildvcs=false \
  -e CGO_ENABLED=1 -e CGO_CFLAGS=-I/pqtls-stage/include -e CGO_LDFLAGS=-L/pqtls-stage/lib -e LD_LIBRARY_PATH=/pqtls-stage/lib \
  -e OPENSSL_CONF=/dev/null -e PQTLS_TEST_OPENSSL=/pqtls-stage/bin/openssl -e "PQTLS_TEST_ARTIFACT_DIR=$evidence" \
  -e PQTLS_TEST_PACKAGE_BINARY=/artifact/bin/cicada -e "PQTLS_TEST_EXPECTED_SOURCE_FINGERPRINT=$fingerprint" \
  -e "PQTLS_TEST_WEBCRYPTO_MANIFEST_SHA256=$wasm_sha" "${env_args[@]}" \
  -w "$repo_root/cicada-go" \
  golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 \
  go test -tags cicada_pqtls -count=1 -json -timeout=3m -run '^TestPQDistributionActualHubNode$' ./cmd/cicada \
  > "$evidence/gate.jsonl" 2>&1 &
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
    docker run --detach --name "$hub" --network "container:$driver" \
      --user "$(id -u):$(id -g)" --cpus 2 --memory 512m --pids-limit 128 \
      -v "${parameters[0]}:${parameters[0]}:ro" -v "${parameters[1]}:${parameters[1]}" \
      -e "CICADA_STATE_DIR=${parameters[1]}" -e "CICADA_WORKSPACE_ROOT=${parameters[0]}/workspace" \
      "$image" serve --fabric-only --host 127.0.0.1 --port "${parameters[3]}" --node-pqtls-config "${parameters[2]}" \
      > "$evidence/hub-container-id.txt"
    hub_started=true
    for ((i=0;i<120;i++)); do
      [[ -f "$request.done" ]] && break
      kill -0 "$driver_pid" 2>/dev/null || break
      if [[ -f "$request.memory-ready" && ! -f "$evidence/hub-idle-docker-stats.json" ]]; then
        docker stats --no-stream --format '{{json .}}' "$hub" > "$evidence/hub-idle-docker-stats.json"
      fi
      sleep 1
    done
    docker stop --time 10 "$hub" > "$evidence/hub-stop.log"
    docker inspect "$hub" > "$evidence/hub-inspect.json"
    docker logs "$hub" > "$evidence/hub.log" 2>&1
    printf 'stopped\n' > "$request.stopped"
  fi
fi
set +e
wait "$driver_pid"
exit_code=$?
set -e
printf '%s\n' "$exit_code" > "$evidence/gate.exit"
python3 "$repo_root/scripts/hub-build-input-inventory.py" verify-distribution "${identity_args[@]}" > "$evidence/identity-after.json"
cmp "$evidence/identity-before.json" "$evidence/identity-after.json"
(cd "$package" && sha256sum --check --status SHA256SUMS)
python3 - "$evidence" "$image" <<'PY'
import collections,hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);counts=collections.Counter();skips=[]
for line in (root/'gate.jsonl').read_text().splitlines():
 try:event=json.loads(line)
 except ValueError:continue
 if event.get('Action') in ('pass','fail','skip'):
  test=event.get('Test');kind='sub' if test and '/' in test else 'top' if test else 'package'
  counts[event['Action']+'_'+kind]+=1
  if event['Action']=='skip':skips.append(event)
result={'process_exit':int((root/'gate.exit').read_text()),'counts':dict(counts),'skip_is_not_pass':True,'skips':skips,'runtime_image':sys.argv[2] or None,'topology':'one Hub/two independent real Node Agent processes; image gate shares an isolated test namespace; not independent PQ Hubs/native/public proof','no_model_provider_native_calls':True}
if (root/'hub-inspect.json').exists():
 inspect=json.loads((root/'hub-inspect.json').read_text())[0];result['hub_exit']=inspect['State']['ExitCode'];result['image_id']=inspect['Image'];result['image_labels']=inspect['Config'].get('Labels');result['container_runtime_user']=inspect['Config']['User']
 if result['hub_exit']!=0:result['process_exit']=1
result['evidence_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir() if p.is_file()}
(root/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('evidence_sha256','image_labels','skips')},sort_keys=True))
raise SystemExit(result['process_exit'])
PY
exit "$exit_code"
