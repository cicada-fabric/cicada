#!/usr/bin/env bash
# Extend only an owned, fixed v1.3 Client fixture with a second logical Node
# and private Android/native handoffs. The Android Client owns all Hub writes.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

usage() {
  printf 'usage: %s bootstrap-remote FIXTURE | stage-group FIXTURE SETUP_JSON | runtime FIXTURE | config FIXTURE PROXY_PORT | sign-groups FIXTURE MANIFESTS_JSON SIGNER | stage-confirmed FIXTURE PREPARED_JSON RESULT_JSON | verify-private FIXTURE\n' "$(basename "$0")" >&2
}

validate() {
  python3 - "$1" <<'PY'
from pathlib import Path
import json, os, re, subprocess, sys, urllib.request
from urllib.parse import urlsplit
root = Path(sys.argv[1])
if not root.is_absolute() or root.parent != Path('/tmp') or not root.name.startswith('cgk.') or root.is_symlink():
    raise SystemExit('BLOCKED: expected an owned, direct /tmp/cgk.* fixture')
stat = root.stat()
if not root.is_dir() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
    raise SystemExit('BLOCKED: fixture directory is not owned/private')
def private(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 262144:
        raise SystemExit('BLOCKED: missing or unsafe private fixture file')
    return json.loads(path.read_text())
marker = private(root / '.cicada-client-group-key-fixture.json')
result = private(root / 'fixture-result.json')
image = 'sha256:a1cf39e4b341cda7d5f80a13b8c3272964f43e5341eadbae1b6caafb6a68a31c'
source = '25013b51915124fa1da25e5fd37088eadf0e3d2d'
catalog = '808f9f635effc5fa845572b976c89696ea2bb86a6a9b6f326e49d1409b570377'
if (marker.get('schema') != 'cicada.client-group-key-fixture.v1' or
        marker.get('fixture_dir') != str(root) or marker.get('image_id') != image or
        marker.get('source_revision') != source or marker.get('catalog_sha256') != catalog or
        marker.get('source_dirty') is not False or marker.get('contract_revision') != 'client-hub-v1.3' or
        result['hub']['image_id'] != image or result['hub']['source_revision'] != source):
    raise SystemExit('BLOCKED: fixture is not the frozen clean v1.3 Hub')
url = result['hub']['url']
if not re.fullmatch(r'http://127\.0\.0\.1:[0-9]{4,5}', url):
    raise SystemExit('BLOCKED: fixture Hub must use loopback')
name = marker.get('hub_container', '')
if not re.fullmatch(r'cicada-cgk-[a-z0-9]+-hub', name):
    raise SystemExit('BLOCKED: fixture Hub container marker is invalid')
actual = json.loads(subprocess.check_output(['docker', 'container', 'inspect', name], text=True))[0]
labels = actual.get('Config', {}).get('Labels') or {}
if (actual.get('Image') != image or not actual.get('State', {}).get('Running') or
        labels.get('org.cicada.fixture') != 'client-group-key' or
        labels.get('org.cicada.fixture.dir') != str(root) or
        labels.get('org.opencontainers.image.revision') != source):
    raise SystemExit('BLOCKED: marked fixed-image disposable Hub is not running')
port = urlsplit(url).port
bindings = (actual.get('NetworkSettings', {}).get('Ports') or {}).get('8787/tcp') or []
if len(bindings) != 1 or bindings[0].get('HostIp') != '127.0.0.1' or bindings[0].get('HostPort') != str(port):
    raise SystemExit('BLOCKED: fixture URL is not the marked Hub loopback port')
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(url + '/healthz', timeout=5) as response: health = json.load(response)
    with opener.open(url + '/v2/client/capabilities', timeout=5) as response: capabilities = json.load(response)
    with opener.open(url + '/v2/client/identity', timeout=5) as response: identity = json.load(response)
except (OSError, ValueError) as error:
    raise SystemExit('BLOCKED: fixed Hub public metadata is unavailable') from error
saved_identity = private(root / 'hub-identity.json')
if (health.get('status') != 'ok' or health.get('revision') != source or
        health.get('dirty') is not False or health.get('source_fingerprint') != marker.get('source_fingerprint') or
        health.get('catalog_sha256') != catalog or capabilities.get('catalog_sha256') != catalog or
        capabilities.get('contract_revision') != 'client-hub-v1.3' or
        identity.get('hub_id') != saved_identity.get('hub_id') or
        identity.get('control_public_identity') != saved_identity.get('control_public_identity')):
    raise SystemExit('BLOCKED: fixture Hub runtime provenance or pinned identity changed')
print(root)
PY
}

bootstrap_remote() {
  local root="$1" local_id remote_id suffix
  python3 - "$root" <<'PY'
from pathlib import Path
import hashlib, json, sys
root = Path(sys.argv[1]); binary = root/'bin/cicada'
expected = json.loads((root/'fixture-result.json').read_text())['fixed_image_cicada_binary_sha256']
if (binary.is_symlink() or not binary.is_file() or not binary.stat().st_mode & 0o111 or
        hashlib.sha256(binary.read_bytes()).hexdigest() != expected):
    raise SystemExit('BLOCKED: remote Node bootstrap requires the fixed-image CICADA executable')
PY
  local_id="$(python3 - "$root/fixture-result.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['node']['node_id'])
PY
)"
  suffix="$(basename "$root" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')"
  remote_id="cgr-${suffix}"
  [[ "$remote_id" != "$local_id" ]] || { printf 'BLOCKED: Node IDs collide\n' >&2; return 2; }
  local remote_join_socket="$root/remote-node-state/nodes/node-$remote_id/join.sock"
  (( ${#remote_join_socket} < 104 )) || { printf 'BLOCKED: remote native Join socket path exceeds its bound\n' >&2; return 2; }
  [[ ! -e "$root/native-monitor-remote-node.json" && ! -L "$root/native-monitor-remote-node.json" ]] || { printf 'BLOCKED: remote Node already bootstrapped\n' >&2; return 2; }
  mkdir -m 700 "$root/remote-node-state"
  local hub_url
  hub_url="$(python3 - "$root/fixture-result.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['hub']['url'])
PY
)"
  python3 - "$root" "$remote_id" "$local_id" "$hub_url" <<'PY'
from pathlib import Path
import json, os, re, subprocess, sys
root, remote, local, hub = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
log = root / 'remote-node-bootstrap.private.log'
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'wb') as out:
    completed = subprocess.run([str(root/'bin/cicada'),'machine','agent','--id',remote,
        '--name','Disposable remote Monitor Node','--control-url',hub,
        '--state-dir',str(root/'remote-node-state'),'--once'],stdout=out,stderr=subprocess.STDOUT,timeout=60)
if completed.returncode != 1:
    raise SystemExit('BLOCKED: remote Node bootstrap returned unexpected state; private log retained')
raw = log.read_text()
match = re.search(r'Device code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}) ', raw)
if not match:
    raise SystemExit('BLOCKED: remote Node yielded no pending pairing code')
local_code = (root / 'node-device-code.txt').read_text().strip()
if not re.fullmatch(r'[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}', local_code):
    raise SystemExit('BLOCKED: original Node pairing code is invalid')
for name, value in (('native-monitor-remote-node.json', {'node_id':remote}),
                    ('native-monitor-node-codes.json', {'local':local_code, 'remote':match.group(1)})):
    fd = os.open(root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as out:
        json.dump(value, out); out.write('\n')
PY
  printf 'READY: two logical disposable Nodes require explicit Android confirmation; code file remains mode 0600\n'
}

stage_group() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import json, os, re, sys
root, source = Path(sys.argv[1]), Path(sys.argv[2])
if source.is_symlink() or not source.is_file() or source.stat().st_mode & 0o077:
    raise SystemExit('BLOCKED: exported Android Group handoff must be a private regular file')
value = json.loads(source.read_text())
group = value.get('group_id')
if not isinstance(group, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', group):
    raise SystemExit('BLOCKED: Android did not export a valid Group ID')
fd = os.open(root / 'native-monitor-group.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as out:
    json.dump({'group_id':group}, out); out.write('\n')
PY
  printf 'READY: Android-created Group ID staged privately\n'
}

runtime() {
  python3 - "$1" "$repo_root/docker/codex-config.toml" <<'PY'
from pathlib import Path
import hashlib, json, os, sys
root, config = map(Path, sys.argv[1:])
target = root / 'native-runtime'
if os.path.lexists(target):
    raise SystemExit('BLOCKED: refusing to replace an existing native runtime')
public_dir = root/'owner-public'
if (public_dir.is_symlink() or not public_dir.is_dir() or
        public_dir.stat().st_uid != os.getuid() or public_dir.stat().st_mode & 0o077):
    raise SystemExit('BLOCKED: Owner public fixture directory is unsafe')
for path in (root/'native-monitor-group.json', root/'native-monitor-remote-node.json',
             root/'owner-public/owner-public.json'):
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: native runtime input is missing or unsafe')
binary = root/'bin/cicada'
expected_sha = json.loads((root/'fixture-result.json').read_text())['fixed_image_cicada_binary_sha256']
if (binary.is_symlink() or not binary.is_file() or not binary.stat().st_mode & 0o111 or
        hashlib.sha256(binary.read_bytes()).hexdigest() != expected_sha or
        config.is_symlink() or not config.is_file()):
    raise SystemExit('BLOCKED: native runtime executable or config differs from fixed input')
target.mkdir(mode=0o700)
for directory in ('owner-public', 'node-state', 'remote-node-state', 'native-codex-home', 'bin'):
    (target/directory).mkdir(mode=0o700)
for relative in ('.cicada-client-group-key-fixture.json', 'fixture-result.json',
                 'native-monitor-group.json', 'native-monitor-remote-node.json',
                 'owner-public/owner-public.json'):
    source = root/relative
    if source.is_symlink() or not source.is_file() or source.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: native runtime metadata is missing or unsafe')
    destination = target/relative
    fd = os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out: out.write(source.read_bytes())
for source, destination, mode in ((root/'bin/cicada',target/'bin/cicada',0o755),
                                  (config,target/'native-codex-home/config.toml',0o600)):
    fd = os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as out: out.write(source.read_bytes())
    destination.chmod(mode)
PY
  printf 'READY: allowlisted native runtime staged; mount only native-runtime and two original Node state directories\n'
}

config() {
  python3 - "$1" "$2" <<'PY'
from pathlib import Path
import base64, json, os, re, sys
root, port = Path(sys.argv[1]), sys.argv[2]
if not re.fullmatch(r'[0-9]{4,5}', port) or not 1024 <= int(port) <= 65535:
    raise SystemExit('BLOCKED: invalid loopback proxy port')
for directory in (root/'owner-public',):
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: fixture projection directory is unsafe')
if os.path.lexists(root/'native-runtime'):
    directory = root/'native-runtime'
    if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: native runtime directory is unsafe')
result = json.loads((root/'fixture-result.json').read_text())
remote = json.loads((root/'native-monitor-remote-node.json').read_text())['node_id']
owner = {'owner_id':result['owner']['owner_id'], 'owner_key_id':result['owner']['owner_key_id'],
         'owner_public_identity':json.loads((root/'owner-public/owner-public.json').read_text())}
grant = root/'monitor-device-grant.json'
if grant.exists():
    if grant.is_symlink() or grant.stat().st_mode & 0o077: raise SystemExit('BLOCKED: Owner device grant is unsafe')
    grant_bytes = grant.read_bytes()
    claims = json.loads(grant_bytes)
    if claims['owner_id'] != owner['owner_id'] or claims['owner_key_id'] != owner['owner_key_id'] or claims['hub_id'] != result['hub']['hub_id']:
        raise SystemExit('BLOCKED: Owner device grant differs from fixture')
    owner['device_id'] = claims['device_id']
    owner['owner_device_grant_base64'] = base64.b64encode(grant_bytes).decode()
cfg = {'schema':'cicada.client-monitor-fixture.v1', 'hub_base_url':'http://127.0.0.1:'+port,
       'hub_identity':json.loads((root/'hub-identity.json').read_text()), 'owner':owner,
       'nodes':[{'label':'local','node_id':result['node']['node_id']},
                {'label':'remote','node_id':remote}]}
group = root/'native-monitor-group.json'
if group.exists(): cfg['group_id'] = json.loads(group.read_text())['group_id']
native = root/'native-runtime/native-monitor-endpoints.json'
if native.exists():
    state = json.loads(native.read_text())
    parties = state.get('Parties', [])
    if (state['GroupID'] != cfg.get('group_id') or state['OwnerID'] != owner['owner_id'] or
            state['HubID'] != result['hub']['hub_id'] or len(parties) != 3 or
            [p.get('Label') for p in parties] != ['monitor','local','remote'] or
            [p.get('NodeID') for p in parties] != [result['node']['node_id'],result['node']['node_id'],remote] or
            len({p.get('ThreadID') for p in parties}) != 3 or
            len({p.get('EndpointID') for p in parties}) != 3 or
            any(not p.get('ThreadID') or not p.get('EndpointID') or not p.get('PrincipalID') for p in parties)):
        raise SystemExit('BLOCKED: native Endpoint handoff differs from Android Group/Owner')
    cfg['endpoints'] = []
    for party in parties:
        item = {'label':{'monitor':'monitor','local':'recipient-a','remote':'recipient-b'}[party['Label']],
                'endpoint_id':party['EndpointID']}
        proof = root/('monitor-proof-'+item['label']+'.json')
        if proof.exists():
            if proof.is_symlink() or proof.stat().st_mode & 0o077: raise SystemExit('BLOCKED: Owner Group proof is unsafe')
            item['owner_signed_proof_base64'] = base64.b64encode(proof.read_bytes()).decode()
        cfg['endpoints'].append(item)
    cfg['monitor_endpoint_id'] = parties[0]['EndpointID']
target = root/'native-monitor-android-fixture.json'
temporary = root/'native-monitor-android-fixture.tmp'
fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
with os.fdopen(fd,'w') as out:
    json.dump(cfg,out,separators=(',',':')); out.write('\n'); out.flush(); os.fsync(out.fileno())
os.replace(temporary,target)
PY
  printf 'READY: public Android fixture material staged in a private file; no Node bearer or Owner private key included\n'
}

sign_groups() {
  python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import hashlib, json, os, subprocess, sys
root, source, signer = map(Path, sys.argv[1:])
if source.is_symlink() or not source.is_file() or source.stat().st_mode & 0o077:
    raise SystemExit('BLOCKED: Android manifests export is not private')
if not signer.is_absolute() or signer.is_symlink() or not signer.is_file() or hashlib.sha256(signer.read_bytes()).hexdigest() != 'cc7ff55659695bffa9daa9b3e3ba0b40cb151d2691d6c60678e7292003a44ae1':
    raise SystemExit('BLOCKED: expected fixed external Owner signer')
owner_private = root/'owner-private/owner-private.json'
if (owner_private.parent.is_symlink() or not owner_private.parent.is_dir() or
        owner_private.parent.stat().st_uid != os.getuid() or owner_private.parent.stat().st_mode & 0o077 or
        owner_private.is_symlink() or not owner_private.is_file() or owner_private.stat().st_mode & 0o077):
    raise SystemExit('BLOCKED: Owner private identity must stay in its protected fixture path')
if (root/'native-runtime').is_symlink() or not (root/'native-runtime').is_dir():
    raise SystemExit('BLOCKED: native runtime directory is unsafe')
state = json.loads((root/'native-runtime/native-monitor-endpoints.json').read_text())
manifests = json.loads(source.read_text())
if set(manifests) != {'monitor','recipient-a','recipient-b'}:
    raise SystemExit('BLOCKED: Android manifest export lacks exact three Endpoints')
fixture = json.loads((root/'fixture-result.json').read_text())
remote = json.loads((root/'native-monitor-remote-node.json').read_text())['node_id']
parties = state.get('Parties', [])
if (state.get('OwnerID') != fixture['owner']['owner_id'] or state.get('HubID') != fixture['hub']['hub_id'] or
        len(parties) != 3 or [p.get('Label') for p in parties] != ['monitor','local','remote'] or
        [p.get('NodeID') for p in parties] != [fixture['node']['node_id'],fixture['node']['node_id'],remote] or
        len({p.get('EndpointID') for p in parties}) != 3):
    raise SystemExit('BLOCKED: native handoff is outside the fixed Owner/Node scope')
try:
    review_tty = os.open('/dev/tty', os.O_RDONLY | os.O_NOCTTY)
except OSError:
    raise SystemExit('BLOCKED: Owner signing requires a controlling terminal for explicit review')
for party in parties:
    label = {'monitor':'monitor','local':'recipient-a','remote':'recipient-b'}[party['Label']]
    manifest = manifests[label]
    epoch = party.get('BindingEpoch')
    if (not isinstance(epoch,int) or isinstance(epoch,bool) or epoch <= 0 or
            not isinstance(manifest.get('binding_epoch'),int) or isinstance(manifest.get('binding_epoch'),bool) or
            not isinstance(party.get('BindingID'),str) or not party['BindingID']):
        raise SystemExit('BLOCKED: native Endpoint binding is incomplete')
    expected = {'owner_id':state['OwnerID'], 'hub_id':state['HubID'], 'group_id':state['GroupID'],
                'endpoint_id':party['EndpointID'], 'node_id':party['NodeID'], 'principal_id':party['PrincipalID'],
                'binding_id':party['BindingID'], 'binding_epoch':epoch}
    if any(manifest.get(k) != v for k,v in expected.items()):
        raise SystemExit('BLOCKED: Owner manifest differs from real native Endpoint identity')
    target = root/('monitor-manifest-'+label+'.json')
    proof = root/('monitor-proof-'+label+'.json')
    if os.path.lexists(target) or os.path.lexists(proof):
        raise SystemExit('BLOCKED: refusing to replace a prior Owner signing artifact')
    fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'w') as out: json.dump(manifest,out,separators=(',',':')); out.write('\n')
    command = [str(signer),'group-grant','--private',str(owner_private),
               '--manifest',str(target),'--expect-owner',state['OwnerID'],'--expect-hub',state['HubID'],
               '--expect-group',state['GroupID'],'--expect-endpoint',party['EndpointID'],
               '--expect-node',party['NodeID'],'--expect-principal',party['PrincipalID'],
               '--expect-digest',manifest['digest'],'--out',str(proof)]
    subprocess.run(command,check=True,stdin=review_tty)
os.close(review_tty)
PY
  printf 'READY: exact Owner-signed proofs remain private; Android must explicitly approve each Group grant\n'
}

stage_confirmed() {
  python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import hashlib, json, os, sys
root, prepared_path, result_path = map(Path, sys.argv[1:])
if (root/'native-runtime').is_symlink() or not (root/'native-runtime').is_dir():
    raise SystemExit('BLOCKED: native runtime directory is unsafe')
for path in (prepared_path,result_path):
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: Android Confirm exports must be private regular files')
prepared, result = json.loads(prepared_path.read_text()), json.loads(result_path.read_text())
native = json.loads((root/'native-runtime/native-monitor-endpoints.json').read_text())
positive = result.get('positive',{})
status = positive.get('status',{})
body = 'Monitor acceptance: 中文与 emoji 🙂\nKeep exact trailing spaces.  \n'
digest = hashlib.sha256(body.encode()).hexdigest()
recipients = [item['endpointId'] for item in prepared.get('recipients',[])]
expected = {native['Parties'][1]['EndpointID'],native['Parties'][2]['EndpointID']}
if (positive.get('result') != 'PASS' or positive.get('body_sha256') != digest or
        prepared.get('bodySha256') != digest or prepared.get('groupId') != native['GroupID'] or
        prepared.get('monitorEndpointId') != native['Parties'][0]['EndpointID'] or
        set(recipients) != expected or len(recipients) != 2 or
        status.get('preview_id') != prepared.get('previewId') or
        status.get('broadcast_id') != prepared.get('broadcastId') or
        status.get('approval_status') not in ('APPROVED','DISPATCH_AUTHORIZED')):
    raise SystemExit('BLOCKED: Android confirmation is not the exact native roster/body/approval')
handoff = {'Schema':'cicada.monitor-android-confirmed.v1','PreviewID':prepared['previewId'],
           'BroadcastID':prepared['broadcastId'],'GroupID':native['GroupID'],
           'MonitorEndpointID':native['Parties'][0]['EndpointID'],'BodySHA256':digest,
           'ApprovalStatus':status['approval_status'],'ExpiresAt':prepared['expiresAt'],
           'recipient_endpoint_ids':recipients}
temporary = root/'native-runtime/native-monitor-confirmed.tmp'
target = root/'native-runtime/native-monitor-confirmed.json'
fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as out:
    json.dump(handoff,out,separators=(',',':')); out.write('\n'); out.flush(); os.fsync(out.fileno())
try:
    os.link(temporary,target)
finally:
    temporary.unlink()
PY
  printf 'READY: exact Android approval handoff staged; Monitor dispatch must meet the original preview deadline\n'
}

verify_private() {
  python3 - "$1" <<'PY'
from pathlib import Path
import json, os, sys
root = Path(sys.argv[1]); runtime = root/'native-runtime'
state_path, chain_path = runtime/'native-monitor-endpoints.json',runtime/'native-monitor-chain.json'
for path in (runtime,state_path,chain_path,root/'state'):
    if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise SystemExit('BLOCKED: native completion or Hub state is not owned/private')
state, chain = json.loads(state_path.read_text()),json.loads(chain_path.read_text())
if (state.get('Schema') != 'cicada.monitor-android-native.v1' or
        chain.get('schema') != 'cicada.monitor-android-native-chain.v1' or
        not chain.get('broadcast_id') or len(chain.get('child_message_ids',[])) != 2 or
        len(state.get('Parties',[])) != 3):
    raise SystemExit('BLOCKED: native delivery did not finish its exact two-child chain')
private = ['Monitor acceptance: 中文与 emoji 🙂\nKeep exact trailing spaces.  \n']
private += [party['Context'] for party in state['Parties']]
database = root/'state/cicada.sqlite3'
found = False
for path in (database,Path(str(database)+'-wal'),Path(str(database)+'-shm')):
    if not path.exists(): continue
    found = True
    if path.is_symlink() or not path.is_file(): raise SystemExit('BLOCKED: Hub database artifact is unsafe')
    data = path.read_bytes()
    encodings = [representation.encode() for value in private for representation in
                 (value,json.dumps(value,ensure_ascii=False),json.dumps(value,ensure_ascii=True))]
    if any(value in data for value in encodings):
        raise SystemExit('FAIL: native private text found in disposable Hub database artifact')
if not found: raise SystemExit('BLOCKED: disposable Hub database artifact is absent')
print('PASS: native chain completion marker and Hub database plaintext scan; private values withheld')
PY
}

if [[ $# -lt 2 ]]; then usage; exit 2; fi
action="$1"
root="$(validate "$2")"
case "$action" in
  bootstrap-remote) [[ $# -eq 2 ]] || { usage; exit 2; }; bootstrap_remote "$root" ;;
  stage-group) [[ $# -eq 3 ]] || { usage; exit 2; }; stage_group "$root" "$3" ;;
  runtime) [[ $# -eq 2 ]] || { usage; exit 2; }; runtime "$root" ;;
  config) [[ $# -eq 3 ]] || { usage; exit 2; }; config "$root" "$3" ;;
  sign-groups) [[ $# -eq 4 ]] || { usage; exit 2; }; sign_groups "$root" "$3" "$4" ;;
  stage-confirmed) [[ $# -eq 4 ]] || { usage; exit 2; }; stage_confirmed "$root" "$3" "$4" ;;
  verify-private) [[ $# -eq 2 ]] || { usage; exit 2; }; verify_private "$root" ;;
  *) usage; exit 2 ;;
esac
