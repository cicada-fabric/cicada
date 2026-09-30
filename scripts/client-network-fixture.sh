#!/usr/bin/env bash
# Disposable f308 Client Network fixture. No Node, model, current-source Store,
# deployment state, or Owner private key is mounted into the Hub.
set -euo pipefail
umask 077

image_id='sha256:56956f8a3d50b7e0445eef4017ba7cecff0ced570694cf8d8c3bb964e060aef7'
revision='f30892fcd79a27bfe5604575deaecebe52c5ec50'
marker_name='.cicada-client-network-fixture.json'

usage() {
  printf 'usage: %s setup | grant FIXTURE_DIR --signer PATH --manifest PATH --device-id ID --device-key-id ID --device-fingerprint SHA256 --expires-at UTC_RFC3339 | cleanup FIXTURE_DIR\n' "$0" >&2
  exit 2
}

validate_fixture() {
  python3 - "$1" "$marker_name" "$image_id" <<'PY'
import json, os, re, sys
from pathlib import Path
requested, marker_name, image_id = sys.argv[1:]
root = Path(requested).resolve(strict=True)
if not re.fullmatch(r'/tmp/cn\.[A-Za-z0-9]{8}', str(root)) or root.is_symlink():
    raise SystemExit('BLOCKED: fixture must be a real /tmp/cn.XXXXXXXX directory')
if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
    raise SystemExit('BLOCKED: fixture ownership or permissions differ')
marker = root / marker_name
if marker.is_symlink() or not marker.is_file() or marker.stat().st_mode & 0o777 != 0o600:
    raise SystemExit('BLOCKED: fixture marker missing or unsafe')
data = json.loads(marker.read_text())
if (data.get('schema') != 'cicada.client-network-fixture.v1'
        or data.get('fixture_dir') != str(root) or data.get('image_id') != image_id
        or not re.fullmatch(r'cicada-cn-[a-z0-9]{10}-hub', data.get('container', ''))
        or not re.fullmatch(r'cicada-cn-[a-z0-9]{10}-net', data.get('network', ''))):
    raise SystemExit('BLOCKED: fixture marker identity mismatch')
print(data['container'])
print(data['network'])
PY
}

check_pinned_image() {
  local details
  details="$(docker image inspect "$image_id")" || { printf 'BLOCKED: pinned f308 image missing\n' >&2; return 2; }
  IMAGE_DETAILS="$details" python3 - "$image_id" "$revision" <<'PY'
import json, os, sys
image = json.loads(os.environ['IMAGE_DETAILS'])[0]
labels = image['Config'].get('Labels') or {}
if (image['Id'] != sys.argv[1]
        or labels.get('org.opencontainers.image.revision') != sys.argv[2]
        or labels.get('org.cicada.build.dirty') != 'false'
        or labels.get('org.cicada.role') != 'hub'):
    raise SystemExit('BLOCKED: pinned f308 Hub image identity/labels mismatch')
PY
}

check_owned_docker() {
  local fixture="$1" container="$2" network="$3"
  python3 - "$fixture" "$container" "$network" "$image_id" <<'PY'
import json, subprocess, sys
root, container, network, image_id = sys.argv[1:]
def inspect(kind, name):
    result = subprocess.run(['docker', kind, 'inspect', name], capture_output=True, text=True)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None
c = inspect('container', container)
if c is not None:
    labels = c['Config'].get('Labels') or {}
    if c['Image'] != image_id or labels.get('org.cicada.fixture') != 'client-network' or labels.get('org.cicada.fixture.dir') != root:
        raise SystemExit('BLOCKED: container is not owned by this fixture')
n = inspect('network', network)
if n is not None:
    labels = n.get('Labels') or {}
    if labels.get('org.cicada.fixture') != 'client-network' or labels.get('org.cicada.fixture.dir') != root:
        raise SystemExit('BLOCKED: Docker network is not owned by this fixture')
PY
}

cleanup() {
  local fixture="$1" identities container network
  identities="$(validate_fixture "$fixture")"
  mapfile -t names <<<"$identities"
  container="${names[0]}"
  network="${names[1]}"
  check_owned_docker "$fixture" "$container" "$network"
  if docker container inspect "$container" >/dev/null 2>&1; then
    docker rm -f "$container" >/dev/null
  fi
  if docker network inspect "$network" >/dev/null 2>&1; then
    docker network rm "$network" >/dev/null
  fi
  python3 - "$fixture" <<'PY'
from pathlib import Path
import shutil, sys
root = Path(sys.argv[1]).resolve(strict=True)
shutil.rmtree(root)
PY
  printf 'Removed disposable Client Network fixture %s\n' "$fixture"
}

start_hub() {
  local fixture="$1" container="$2" network="$3" host_uid="$4" host_gid="$5"
  docker run --rm -d --name "$container" --user "${host_uid}:${host_gid}" \
    --network "$network" --label 'org.cicada.fixture=client-network' \
    --label "org.cicada.fixture.dir=$fixture" \
    -p '127.0.0.1::8787' --env-file "$fixture/hub.env" \
    -v "$fixture/state:/state" -v "$fixture/workspace:/workspace" \
    "$image_id" serve --host 0.0.0.0 --port 8787 >/dev/null
}

wait_identity() {
  local container="$1" port
  port="$(docker port "$container" 8787/tcp | python3 -c 'import sys; print(sys.stdin.read().strip().rsplit(":",1)[-1])')"
  python3 - "http://127.0.0.1:$port" <<'PY'
import json, sys, time, urllib.request
url = sys.argv[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(60):
    try:
        with opener.open(url + '/healthz', timeout=2) as response:
            if json.load(response).get('status') == 'ok':
                with opener.open(url + '/v2/client/identity', timeout=3) as identity:
                    print(url)
                    print(json.dumps(json.load(identity)))
                raise SystemExit(0)
    except (OSError, ValueError):
        time.sleep(.5)
raise SystemExit('BLOCKED: f308 Hub failed health/identity readiness')
PY
}

setup() {
  command -v docker >/dev/null && command -v python3 >/dev/null || { printf 'BLOCKED: Docker and Python 3 required\n' >&2; return 2; }
  check_pinned_image
  local fixture suffix container network owner_id host_uid host_gid identity_before identity_after hub_url hub_id owner_key_id network_id
  fixture="$(mktemp -d /tmp/cn.XXXXXXXX)"
  chmod 0700 "$fixture"
  suffix="$(basename "$fixture" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')"
  container="cicada-cn-${suffix}-hub"
  network="cicada-cn-${suffix}-net"
  owner_id="synthetic_owner_${suffix}"
  host_uid="$(id -u)"; host_gid="$(id -g)"
  mkdir -m 0700 "$fixture/state" "$fixture/workspace" "$fixture/owner-private" "$fixture/owner-public"
  python3 - "$fixture" "$marker_name" "$image_id" "$container" "$network" <<'PY'
import json, secrets, sys
from pathlib import Path
root = Path(sys.argv[1])
(root / sys.argv[2]).write_text(json.dumps({'schema':'cicada.client-network-fixture.v1',
    'fixture_dir':str(root), 'image_id':sys.argv[3], 'container':sys.argv[4], 'network':sys.argv[5]})+'\n')
(root / 'hub.env').write_text('CICADA_API_TOKEN='+secrets.token_hex(32)+'\n')
PY
  chmod 0600 "$fixture/$marker_name" "$fixture/hub.env"
  trap 'printf "Setup failed; inspect and clean fixture: %s\n" "$fixture" >&2' ERR
  docker network create --label 'org.cicada.fixture=client-network' --label "org.cicada.fixture.dir=$fixture" "$network" >/dev/null
  docker run --rm --user "${host_uid}:${host_gid}" \
    -v "$fixture/owner-private:/owner-private" -v "$fixture/owner-public:/owner-public" \
    "$image_id" owner-key generate --private /owner-private/owner-private.json \
    --public /owner-public/owner-public.json >"$fixture/keygen.json"
  owner_key_id="$(python3 - "$fixture/keygen.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['key_id'])
PY
)"
  rm "$fixture/keygen.json"
  start_hub "$fixture" "$container" "$network" "$host_uid" "$host_gid"
  identity_before="$(wait_identity "$container")"
  hub_id="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read().splitlines()[1])["hub_id"])' <<<"$identity_before")"
  docker stop --time 10 "$container" >/dev/null
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    -v "$fixture/owner-public:/owner-public:ro" "$image_id" owner-key register \
    --db /state/cicada.sqlite3 --owner-id "$owner_id" \
    --public /owner-public/owner-public.json --expect-key-id "$owner_key_id" >"$fixture/owner-registration.json"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network create --db /state/cicada.sqlite3 --hub "$hub_id" \
    --name 'Synthetic Client Network' --owner "$owner_id" >"$fixture/network.json"
  network_id="$(python3 - "$fixture/network.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['network_id'])
PY
)"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network activate --db /state/cicada.sqlite3 >"$fixture/network-mode.json"
  python3 - "$fixture/network-mode.json" <<'PY'
import json,sys
if json.load(open(sys.argv[1]))['phase'] != 'ACTIVE':
    raise SystemExit('BLOCKED: Network mode did not activate')
PY
  start_hub "$fixture" "$container" "$network" "$host_uid" "$host_gid"
  identity_after="$(wait_identity "$container")"
  [[ "${identity_before#*$'\n'}" == "${identity_after#*$'\n'}" ]] || { printf 'BLOCKED: Hub identity changed across offline setup\n' >&2; return 2; }
  hub_url="${identity_after%%$'\n'*}"
  python3 - "$fixture" "$hub_url" "$owner_id" "$owner_key_id" "$network_id" "$network" "$image_id" "$revision" "${identity_after#*$'\n'}" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
identity = json.loads(sys.argv[9])
owner_public = json.loads((root/'owner-public/owner-public.json').read_text())
result = {'schema':'cicada.client-network-fixture-result.v1',
    'status':'ACTIVE_NETWORK_AWAITING_CLIENT_GROUP_CREATE', 'base_url':sys.argv[2],
    'hub_id':identity['hub_id'], 'control_public_identity':identity['control_public_identity'],
    'owner_id':sys.argv[3], 'owner_key_id':sys.argv[4], 'owner_public_identity':owner_public,
    'network_id':sys.argv[5], 'docker_network':sys.argv[6], 'image_id':sys.argv[7],
    'source_revision':sys.argv[8], 'device_id':None, 'owner_device_grant':None,
    'group_id':None, 'group_create':'NOT_RUN', 'physical_android':'NOT_RUN', 'public_https':'NOT_RUN'}
(root/'client-public.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
PY
  chmod 0600 "$fixture/client-public.json" "$fixture/owner-registration.json" "$fixture/network.json" "$fixture/network-mode.json"
  trap - ERR
  printf 'Fixture: %s\nClient public fields: %s/client-public.json\nOwner private key (host only): %s/owner-private/owner-private.json\nHub URL: %s\nNetwork: %s\nDocker network: %s\nGroup: Client encrypted group.create still required\n' "$fixture" "$fixture" "$fixture" "$hub_url" "$network_id" "$network"
}

grant() {
  (( $# == 13 )) || usage
  local fixture="$1" signer manifest device_id device_key_id fingerprint expiry key_id hub_id owner_id out
  validate_fixture "$fixture" >/dev/null
  [[ "$2" == --signer && "$4" == --manifest && "$6" == --device-id && "$8" == --device-key-id && "${10}" == --device-fingerprint && "${12}" == --expires-at ]] || usage
  signer="$3"; manifest="$5"; device_id="$7"; device_key_id="$9"; fingerprint="${11}"; expiry="${13}"
  [[ -f "$signer" && -x "$signer" && -f "$manifest" ]] || { printf 'BLOCKED: signer/manifest unavailable\n' >&2; return 2; }
  readarray -t fields < <(python3 - "$fixture/client-public.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(d['owner_id']);print(d['owner_key_id']);print(d['hub_id'])
PY
)
  owner_id="${fields[0]}"; key_id="${fields[1]}"; hub_id="${fields[2]}"
  out="$fixture/owner-device-grant.json"
  [[ ! -e "$out" ]] || { printf 'BLOCKED: grant already exists; use a new fixture for another device\n' >&2; return 2; }
  "$signer" owner device-grant-sign --private "$fixture/owner-private/owner-private.json" \
    --manifest "$manifest" --output "$out" --expect-owner-id "$owner_id" \
    --expect-owner-key-id "$key_id" --expect-hub-id "$hub_id" \
    --expect-device-id "$device_id" --expect-device-key-id "$device_key_id" \
    --expect-device-fingerprint "$fingerprint" --expires-at "$expiry" >"$fixture/grant-result.json"
  python3 - "$fixture/client-public.json" "$out" "$device_id" <<'PY'
import json,os,sys
from pathlib import Path
path=Path(sys.argv[1]); result=json.loads(path.read_text())
result['device_id']=sys.argv[3]
result['owner_device_grant']=json.loads(Path(sys.argv[2]).read_text())
tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');tmp.chmod(0o600);os.replace(tmp,path)
PY
  chmod 0600 "$out" "$fixture/grant-result.json" "$fixture/client-public.json"
  printf 'Signed exact synthetic Android device grant: %s\nClient public fields: %s/client-public.json\n' "$out" "$fixture"
}

case "${1:-}" in
  setup) (( $# == 1 )) || usage; setup ;;
  grant) shift; grant "$@" ;;
  cleanup) (( $# == 2 )) || usage; cleanup "$2" ;;
  *) usage ;;
esac
