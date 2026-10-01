#!/usr/bin/env bash
# Disposable Client Network fixture. All identities are synthetic; Owner
# private keys remain host-only and are never mounted into the Hub container.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
image_id=''
revision=''
catalog_sha256=''
source_fingerprint=''
contract_revision=''
image_reference=''
marker_name='.cicada-client-network-fixture.json'

usage() {
  printf 'usage: %s setup --build-metadata PATH | grant FIXTURE_DIR --signer PATH --manifest PATH --device-id ID --device-key-id ID --device-fingerprint SHA256 --expires-at UTC_RFC3339 | cleanup FIXTURE_DIR\n' "$0" >&2
  exit 2
}

load_build_metadata() {
  local output
  output="$(python3 - "$1" "$repo_root/cicada-go/internal/clientcontract/catalog.json" <<'PY'
import hashlib, json, re, sys
from pathlib import Path
path, catalog_path = map(Path, sys.argv[1:])
if path.is_symlink() or not path.is_file():
    raise SystemExit('BLOCKED: build metadata must be a regular file')
try:
    data = json.loads(path.read_text(encoding='utf-8'))
    catalog_bytes = catalog_path.read_bytes()
    catalog = json.loads(catalog_bytes)
except (OSError, UnicodeError, ValueError):
    raise SystemExit('BLOCKED: build metadata/catalog is invalid')
source, image = data.get('source'), data.get('image')
if data.get('schema_version') != 'cicada.hub-build.v1' or not isinstance(source, dict) or not isinstance(image, dict):
    raise SystemExit('BLOCKED: expected cicada.hub-build.v1 build metadata')
revision, fingerprint, catalog_sha = source.get('revision'), source.get('source_fingerprint'), source.get('catalog_sha256')
image_id, reference = image.get('id'), image.get('reference')
tag = reference.split('@', 1)[0].rsplit(':', 1)[-1] if isinstance(reference, str) else ''
contract = catalog.get('contract_revision') if isinstance(catalog, dict) else None
if (source.get('dirty') is not False
        or not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision)
        or not isinstance(fingerprint, str) or not re.fullmatch(r'[0-9a-f]{64}', fingerprint)
        or not isinstance(catalog_sha, str) or not re.fullmatch(r'[0-9a-f]{64}', catalog_sha)
        or catalog_sha != hashlib.sha256(catalog_bytes).hexdigest()
        or not isinstance(image_id, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id)
        or image.get('dockerfile') != 'docker/Dockerfile.hub'
        or not isinstance(reference, str) or not reference.strip() or tag == 'latest'
        or not isinstance(contract, str) or not re.fullmatch(r'client-hub-v[0-9]+(?:\.[0-9]+)*', contract)):
    raise SystemExit('BLOCKED: metadata is dirty, malformed, or not bound to the authoritative catalog')
print(image_id); print(revision); print(catalog_sha); print(fingerprint); print(contract); print(reference)
PY
)"
  local -a fields=()
  mapfile -t fields <<<"$output"
  [[ "${#fields[@]}" -eq 6 ]] || { printf 'BLOCKED: incomplete build metadata identity\n' >&2; return 2; }
  image_id="${fields[0]}"; revision="${fields[1]}"; catalog_sha256="${fields[2]}"
  source_fingerprint="${fields[3]}"; contract_revision="${fields[4]}"; image_reference="${fields[5]}"
}

validate_fixture() {
  python3 - "$1" "$marker_name" <<'PY'
import json, os, re, sys
from pathlib import Path
requested, marker_name = sys.argv[1:]
requested_path = Path(requested)
if requested_path.is_symlink():
    raise SystemExit('BLOCKED: fixture directory may not be a symlink')
root = requested_path.resolve(strict=True)
if not re.fullmatch(r'/tmp/cn\.[A-Za-z0-9]{8}', str(root)):
    raise SystemExit('BLOCKED: fixture must be a real /tmp/cn.XXXXXXXX directory')
if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o777 != 0o700:
    raise SystemExit('BLOCKED: fixture ownership or permissions differ')
marker = root / marker_name
if marker.is_symlink() or not marker.is_file() or marker.stat().st_mode & 0o777 != 0o600:
    raise SystemExit('BLOCKED: fixture marker missing or unsafe')
data = json.loads(marker.read_text())
if (data.get('schema') != 'cicada.client-network-fixture.v2'
        or data.get('fixture_dir') != str(root)
        or not re.fullmatch(r'sha256:[0-9a-f]{64}', data.get('image_id', ''))
        or not re.fullmatch(r'[0-9a-f]{40}', data.get('source_revision', ''))
        or data.get('source_dirty') is not False
        or not re.fullmatch(r'[0-9a-f]{64}', data.get('catalog_sha256', ''))
        or not re.fullmatch(r'[0-9a-f]{64}', data.get('source_fingerprint', ''))
        or not re.fullmatch(r'client-hub-v[0-9]+(?:\.[0-9]+)*', data.get('contract_revision', ''))
        or not re.fullmatch(r'cicada-cn-[a-z0-9]{10}-hub', data.get('container', ''))
        or not re.fullmatch(r'cicada-cn-[a-z0-9]{10}-net', data.get('network', ''))
        or type(data.get('host_port')) is not int or not 1024 <= data['host_port'] <= 65535):
    raise SystemExit('BLOCKED: fixture marker identity/build pins mismatch')
print(data['container'])
print(data['network'])
print(data['image_id'])
print(data['source_revision'])
print(data['catalog_sha256'])
print(data['source_fingerprint'])
print(data['contract_revision'])
PY
}

check_pinned_image() {
  local details
  details="$(docker image inspect "$image_id")" || { printf 'BLOCKED: build-metadata image is not present locally: %s\n' "$image_id" >&2; return 2; }
  IMAGE_DETAILS="$details" python3 - "$image_id" "$revision" "$catalog_sha256" "$source_fingerprint" <<'PY'
import json, os, sys
image = json.loads(os.environ['IMAGE_DETAILS'])[0]
labels = image['Config'].get('Labels') or {}
if (image['Id'] != sys.argv[1]
        or labels.get('org.opencontainers.image.revision') != sys.argv[2]
        or labels.get('org.cicada.build.dirty') != 'false'
        or labels.get('org.cicada.build.source-fingerprint') != sys.argv[4]
        or labels.get('org.cicada.client-catalog.sha256') != sys.argv[3]
        or labels.get('org.cicada.role') != 'hub'):
    raise SystemExit('BLOCKED: Hub image identity/provenance labels differ from build metadata')
PY
}

check_owned_docker() {
  local fixture="$1" container="$2" network="$3" expected_image="$4" expected_revision="$5" expected_catalog="$6" expected_fingerprint="$7"
  python3 - "$fixture" "$container" "$network" "$expected_image" "$expected_revision" "$expected_catalog" "$expected_fingerprint" <<'PY'
import json, subprocess, sys
root, container, network, image_id, revision, catalog, fingerprint = sys.argv[1:]
def inspect(kind, name):
    result = subprocess.run(['docker', kind, 'inspect', name], capture_output=True, text=True)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None
c = inspect('container', container)
if c is not None:
    labels = c['Config'].get('Labels') or {}
    if (c['Image'] != image_id or labels.get('org.cicada.fixture') != 'client-network'
            or labels.get('org.cicada.fixture.dir') != root
            or labels.get('org.cicada.fixture.source.revision') != revision
            or labels.get('org.cicada.fixture.catalog.sha256') != catalog
            or labels.get('org.cicada.fixture.source.fingerprint') != fingerprint
            or labels.get('org.opencontainers.image.revision') != revision
            or labels.get('org.cicada.build.dirty') != 'false'
            or labels.get('org.cicada.build.source-fingerprint') != fingerprint
            or labels.get('org.cicada.client-catalog.sha256') != catalog
            or labels.get('org.cicada.role') != 'hub'):
        raise SystemExit('BLOCKED: container is not owned by this fixture')
n = inspect('network', network)
if n is not None:
    labels = n.get('Labels') or {}
    if (labels.get('org.cicada.fixture') != 'client-network'
            or labels.get('org.cicada.fixture.dir') != root
            or labels.get('org.cicada.fixture.source.revision') != revision
            or labels.get('org.cicada.fixture.catalog.sha256') != catalog
            or labels.get('org.cicada.fixture.source.fingerprint') != fingerprint):
        raise SystemExit('BLOCKED: Docker network is not owned by this fixture')
PY
}

cleanup() {
  local fixture="$1" identities container network expected_image expected_revision expected_catalog expected_fingerprint
  identities="$(validate_fixture "$fixture")"
  mapfile -t names <<<"$identities"
  container="${names[0]}"; network="${names[1]}"; expected_image="${names[2]}"
  expected_revision="${names[3]}"; expected_catalog="${names[4]}"; expected_fingerprint="${names[5]}"
  check_owned_docker "$fixture" "$container" "$network" "$expected_image" "$expected_revision" "$expected_catalog" "$expected_fingerprint"
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
  local fixture="$1" container="$2" network="$3" host_port="$4" host_uid="$5" host_gid="$6"
  docker run --rm -d --name "$container" --user "${host_uid}:${host_gid}" \
    --network "$network" --label 'org.cicada.fixture=client-network' \
    --label "org.cicada.fixture.dir=$fixture" \
    --label "org.cicada.fixture.source.revision=$revision" \
    --label "org.cicada.fixture.catalog.sha256=$catalog_sha256" \
    --label "org.cicada.fixture.source.fingerprint=$source_fingerprint" \
    -p "127.0.0.1:${host_port}:8787" --env-file "$fixture/hub.env" \
    -v "$fixture/state:/state" -v "$fixture/workspace:/workspace" \
    "$image_id" serve --host 0.0.0.0 --port 8787 >/dev/null
}

wait_identity() {
  local host_port="$1"
  python3 - "http://127.0.0.1:$host_port" "$revision" "$catalog_sha256" "$source_fingerprint" "$contract_revision" <<'PY'
import json, sys, time, urllib.request
url, revision, catalog_sha, fingerprint, contract = sys.argv[1:]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(60):
    try:
        with opener.open(url + '/healthz', timeout=2) as response:
            health = json.load(response)
        with opener.open(url + '/v2/client/capabilities', timeout=3) as response:
            capabilities = json.load(response)
        with opener.open(url + '/v2/client/identity', timeout=3) as response:
            identity = json.load(response)
        if (health.get('status') == 'ok' and health.get('revision') == revision
                and health.get('dirty') is False and health.get('source_fingerprint') == fingerprint
                and health.get('catalog_sha256') == catalog_sha
                and capabilities.get('contract_revision') == contract
                and capabilities.get('catalog_sha256') == catalog_sha):
            print(url)
            print(json.dumps(identity, sort_keys=True, separators=(',', ':')))
            raise SystemExit(0)
    except (OSError, ValueError):
        time.sleep(.5)
raise SystemExit('BLOCKED: Hub failed pinned health/capability/identity readiness')
PY
}

setup() {
  command -v docker >/dev/null && command -v python3 >/dev/null || { printf 'BLOCKED: Docker and Python 3 required\n' >&2; return 2; }
  docker info >/dev/null 2>&1 || { printf 'BLOCKED: Docker daemon unavailable\n' >&2; return 2; }
  check_pinned_image
  local fixture suffix container network primary_owner foreign_owner host_uid host_gid host_port
  local identity_before identity_after hub_url hub_id primary_key_id foreign_key_id primary_network foreign_network
  fixture="$(mktemp -d /tmp/cn.XXXXXXXX)"
  chmod 0700 "$fixture"
  suffix="$(basename "$fixture" | tr '[:upper:]' '[:lower:]' | tr -cd '[:alnum:]')"
  container="cicada-cn-${suffix}-hub"
  network="cicada-cn-${suffix}-net"
  primary_owner="synthetic_owner_${suffix}"
  foreign_owner="synthetic_foreign_owner_${suffix}"
  host_uid="$(id -u)"; host_gid="$(id -g)"
  host_port="$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    print(sock.getsockname()[1])
PY
)"
  mkdir -m 0700 "$fixture/state" "$fixture/workspace" "$fixture/owner-private" "$fixture/owner-public"
  python3 - "$fixture" "$marker_name" "$image_id" "$image_reference" "$revision" "$catalog_sha256" \
    "$source_fingerprint" "$contract_revision" "$container" "$network" "$host_port" <<'PY'
import json, secrets, sys
from pathlib import Path
root = Path(sys.argv[1])
(root / sys.argv[2]).write_text(json.dumps({
    'schema':'cicada.client-network-fixture.v2', 'fixture_dir':str(root),
    'image_id':sys.argv[3], 'image_reference':sys.argv[4], 'source_revision':sys.argv[5],
    'source_dirty':False, 'catalog_sha256':sys.argv[6], 'source_fingerprint':sys.argv[7],
    'contract_revision':sys.argv[8], 'container':sys.argv[9], 'network':sys.argv[10],
    'host_port':int(sys.argv[11]), 'recovery':'PENDING'}, sort_keys=True, indent=2)+'\n')
(root / 'hub.env').write_text('CICADA_API_TOKEN='+secrets.token_hex(32)+'\n')
PY
  chmod 0600 "$fixture/$marker_name" "$fixture/hub.env"
  trap 'printf "Setup failed; inspect and clean fixture: %s\n" "$fixture" >&2' ERR
  docker network create --label 'org.cicada.fixture=client-network' \
    --label "org.cicada.fixture.dir=$fixture" \
    --label "org.cicada.fixture.source.revision=$revision" \
    --label "org.cicada.fixture.catalog.sha256=$catalog_sha256" \
    --label "org.cicada.fixture.source.fingerprint=$source_fingerprint" "$network" >/dev/null
  docker run --rm --user "${host_uid}:${host_gid}" \
    -v "$fixture/owner-private:/owner-private" -v "$fixture/owner-public:/owner-public" \
    "$image_id" owner-key generate --private /owner-private/owner-private.json \
    --public /owner-public/owner-public.json >"$fixture/keygen.json"
  primary_key_id="$(python3 - "$fixture/keygen.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['key_id'])
PY
)"
  rm "$fixture/keygen.json"
  docker run --rm --user "${host_uid}:${host_gid}" \
    -v "$fixture/owner-private:/owner-private" -v "$fixture/owner-public:/owner-public" \
    "$image_id" owner-key generate --private /owner-private/foreign-owner-private.json \
    --public /owner-public/foreign-owner-public.json >"$fixture/keygen-foreign.json"
  foreign_key_id="$(python3 - "$fixture/keygen-foreign.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['key_id'])
PY
)"
  rm "$fixture/keygen-foreign.json"
  start_hub "$fixture" "$container" "$network" "$host_port" "$host_uid" "$host_gid"
  identity_before="$(wait_identity "$host_port")"
  hub_id="$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read().splitlines()[1])["hub_id"])' <<<"$identity_before")"
  docker stop --time 10 "$container" >/dev/null
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    -v "$fixture/owner-public:/owner-public:ro" "$image_id" owner-key register \
    --db /state/cicada.sqlite3 --owner-id "$primary_owner" \
    --public /owner-public/owner-public.json --expect-key-id "$primary_key_id" >"$fixture/owner-registration.json"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    -v "$fixture/owner-public:/owner-public:ro" "$image_id" owner-key register \
    --db /state/cicada.sqlite3 --owner-id "$foreign_owner" \
    --public /owner-public/foreign-owner-public.json --expect-key-id "$foreign_key_id" >"$fixture/owner-registration-foreign.json"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network create --db /state/cicada.sqlite3 --hub "$hub_id" \
    --name 'Synthetic Client Network' --owner "$primary_owner" >"$fixture/network.json"
  primary_network="$(python3 - "$fixture/network.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['network_id'])
PY
)"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network create --db /state/cicada.sqlite3 --hub "$hub_id" \
    --name 'Synthetic Foreign Owner Network' --owner "$foreign_owner" >"$fixture/network-foreign.json"
  foreign_network="$(python3 - "$fixture/network-foreign.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['network_id'])
PY
)"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network activate --db /state/cicada.sqlite3 >"$fixture/network-mode.json"
  docker run --rm --user "${host_uid}:${host_gid}" -v "$fixture/state:/state" \
    "$image_id" network list --db /state/cicada.sqlite3 >"$fixture/network-list-after-restart.json"
  python3 - "$fixture/network-mode.json" "$fixture/network-list-after-restart.json" \
    "$primary_owner" "$foreign_owner" "$primary_network" "$foreign_network" <<'PY'
import json,sys
mode, data = (json.load(open(path)) for path in sys.argv[1:3])
owners, networks = set(sys.argv[3:5]), set(sys.argv[5:7])
rows = data.get('networks', [])
if (mode.get('phase') != 'ACTIVE' or data.get('phase') != 'ACTIVE'
        or {x.get('owner_id') for x in rows} != owners
        or {x.get('network_id') for x in rows} != networks):
    raise SystemExit('BLOCKED: same-DB restart did not recover both active Owner Networks')
PY
  start_hub "$fixture" "$container" "$network" "$host_port" "$host_uid" "$host_gid"
  identity_after="$(wait_identity "$host_port")"
  [[ "${identity_before#*$'\n'}" == "${identity_after#*$'\n'}" ]] || { printf 'BLOCKED: Hub identity changed across same-DB restart\n' >&2; return 2; }
  hub_url="${identity_after%%$'\n'*}"
  python3 - "$fixture" "$hub_url" "$hub_id" "$primary_owner" "$primary_key_id" "$primary_network" \
    "$foreign_owner" "$foreign_key_id" "$foreign_network" "$network" "$host_port" \
    "${identity_after#*$'\n'}" <<'PY'
import json, sys
from pathlib import Path
root = Path(sys.argv[1])
identity = json.loads(sys.argv[12])
owner_public = json.loads((root/'owner-public/owner-public.json').read_text())
foreign_public = json.loads((root/'owner-public/foreign-owner-public.json').read_text())
metadata = json.loads((root/'.cicada-client-network-fixture.json').read_text())
result = {'schema':'cicada.client-network-fixture-result.v2',
    'status':'ACTIVE_TWO_OWNER_NETWORKS_AWAITING_CLIENT_GROUP_CREATE', 'base_url':sys.argv[2],
    'hub_id':sys.argv[3], 'control_public_identity':identity['control_public_identity'],
    'owner_id':sys.argv[4], 'owner_key_id':sys.argv[5], 'owner_public_identity':owner_public,
    'network_id':sys.argv[6], 'foreign_owner_id':sys.argv[7], 'foreign_owner_key_id':sys.argv[8],
    'foreign_owner_public_identity':foreign_public, 'foreign_network_id':sys.argv[9],
    'docker_network':sys.argv[10], 'host_port':int(sys.argv[11]),
    'image_id':metadata['image_id'], 'source_revision':metadata['source_revision'],
    'source_fingerprint':metadata['source_fingerprint'], 'catalog_sha256':metadata['catalog_sha256'],
    'contract_revision':metadata['contract_revision'], 'device_id':None, 'group_id':None,
    'group_create':'NOT_RUN', 'same_db_restart':'PASS', 'physical_android':'NOT_RUN', 'public_https':'NOT_RUN'}
(root/'client-public.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
metadata.update({'hub_id':sys.argv[3], 'primary_owner_id':sys.argv[4], 'primary_owner_key_id':sys.argv[5],
    'primary_network_id':sys.argv[6], 'foreign_owner_id':sys.argv[7], 'foreign_owner_key_id':sys.argv[8],
    'foreign_network_id':sys.argv[9], 'recovery':'PASS_SAME_DB_RESTART_IDENTITY_AND_NETWORKS'})
(root/'.cicada-client-network-fixture.json').write_text(json.dumps(metadata,indent=2,sort_keys=True)+'\n')
PY
  chmod 0600 "$fixture/$marker_name" "$fixture/client-public.json" "$fixture/owner-registration.json" \
    "$fixture/owner-registration-foreign.json" "$fixture/network.json" "$fixture/network-foreign.json" \
    "$fixture/network-mode.json" "$fixture/network-list-after-restart.json"
  trap - ERR
  printf 'Fixture: %s\nClient public fields: %s/client-public.json\nOwner private key (host only): %s/owner-private/owner-private.json\nForeign Owner private key (host only): %s/owner-private/foreign-owner-private.json\nHub URL: %s\nPrimary Network: %s\nForeign Network: %s\nDocker network: %s\nGroup: Client encrypted topology.apply still required\n' \
    "$fixture" "$fixture" "$fixture" "$fixture" "$hub_url" "$primary_network" "$foreign_network" "$network"
}

grant() {
  local fixture="$1" signer manifest device_id device_key_id fingerprint expiry hub_id owner_id key_id out selected_owner=primary
  (( $# == 13 || $# == 15 )) || usage
  shift
  if [[ "$1" == --owner ]]; then selected_owner="$2"; shift 2; fi
  [[ "$selected_owner" == primary || "$selected_owner" == foreign ]] || usage
  [[ "$1" == --signer && "$3" == --manifest && "$5" == --device-id && "$7" == --device-key-id && "$9" == --device-fingerprint && "${11}" == --expires-at ]] || usage
  signer="$2"; manifest="$4"; device_id="$6"; device_key_id="$8"; fingerprint="${10}"; expiry="${12}"
  [[ -f "$signer" && -x "$signer" && -f "$manifest" && ! -L "$manifest" ]] || { printf 'BLOCKED: signer/manifest unavailable or unsafe\n' >&2; return 2; }
  local fixture_fields container network expected_image expected_revision expected_catalog expected_fingerprint
  fixture_fields="$(validate_fixture "$fixture")"
  mapfile -t fields <<<"$fixture_fields"
  container="${fields[0]}"; network="${fields[1]}"; expected_image="${fields[2]}"
  expected_revision="${fields[3]}"; expected_catalog="${fields[4]}"; expected_fingerprint="${fields[5]}"
  check_owned_docker "$fixture" "$container" "$network" "$expected_image" "$expected_revision" "$expected_catalog" "$expected_fingerprint"
  readarray -t owner_fields < <(python3 - "$fixture/client-public.json" "$selected_owner" <<'PY'
import json,sys
data=json.load(open(sys.argv[1], encoding='utf-8'))
if sys.argv[2] == 'foreign':
    print(data['foreign_owner_id']); print(data['foreign_owner_key_id'])
else:
    print(data['owner_id']); print(data['owner_key_id'])
print(data['hub_id'])
PY
)
  owner_id="${owner_fields[0]}"; key_id="${owner_fields[1]}"; hub_id="${owner_fields[2]}"
  local private_key
  if [[ "$selected_owner" == foreign ]]; then
    private_key="$fixture/owner-private/foreign-owner-private.json"
  else
    private_key="$fixture/owner-private/owner-private.json"
  fi
  [[ -f "$private_key" && ! -L "$private_key" && "$(stat -c '%a' "$private_key")" == 600 ]] || {
    printf 'BLOCKED: synthetic Owner private key missing or not mode 0600\n' >&2; return 2;
  }
  out="$fixture/owner-device-grant-${selected_owner}.json"
  [[ ! -e "$out" ]] || { printf 'BLOCKED: grant already exists; use a new fixture for another device\n' >&2; return 2; }
  "$signer" owner device-grant-sign --private "$private_key" \
    --manifest "$manifest" --output "$out" --expect-owner-id "$owner_id" \
    --expect-owner-key-id "$key_id" --expect-hub-id "$hub_id" \
    --expect-device-id "$device_id" --expect-device-key-id "$device_key_id" \
    --expect-device-fingerprint "$fingerprint" --expires-at "$expiry" >"$fixture/grant-result-${selected_owner}.json"
  chmod 0600 "$out" "$fixture/grant-result-${selected_owner}.json"
  printf 'Signed exact synthetic %s Owner device grant: %s\nClient public metadata (grant kept separate): %s/client-public.json\n' "$selected_owner" "$out" "$fixture"
}

case "${1:-}" in
  setup) [[ $# == 3 && "$2" == --build-metadata ]] || usage; load_build_metadata "$3"; setup ;;
  grant) shift; grant "$@" ;;
  cleanup) (( $# == 2 )) || usage; cleanup "$2" ;;
  *) usage ;;
esac
