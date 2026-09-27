#!/usr/bin/env bash
# Prepare or remove an isolated Client Group-key validation fixture.
# This script deliberately stops before creating a native Endpoint: that must
# happen from a live Codex Thread through the owner-bound Node's local bridge.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
image_id='sha256:adca1c62db5747625141be4506c4f3713368260076c50876776b4dabafa6c1b7'
expected_revision='967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a'
expected_catalog='25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9'
marker_name='.cicada-client-group-key-fixture.json'
extract_name=''
extract_id=''

usage() {
  printf 'usage: %s start | stop FIXTURE_DIR\n' "$(basename "$0")" >&2
}

real_tmp_root() {
  python3 - <<'PY'
from pathlib import Path
import os
tmp = Path('/tmp').resolve(strict=True)
if str(tmp) != '/tmp':
    raise SystemExit('BLOCKED: /tmp is not a real /tmp directory')
print(tmp)
PY
}

validate_fixture_dir() {
  python3 - "$1" "$marker_name" <<'PY'
from pathlib import Path
import json
import os
import sys

requested, marker_name = sys.argv[1:]
root = Path(requested).resolve(strict=True)
tmp = Path('/tmp').resolve(strict=True)
if os.path.commonpath((str(root), str(tmp))) != str(tmp) or root == tmp:
    raise SystemExit('BLOCKED: fixture directory must resolve beneath real /tmp')
marker = root / marker_name
try:
    data = json.loads(marker.read_text())
except (OSError, ValueError):
    raise SystemExit('BLOCKED: fixture marker is missing or invalid')
if data.get('fixture_dir') != str(root) or data.get('schema') != 'cicada.client-group-key-fixture.v1':
    raise SystemExit('BLOCKED: fixture marker does not match the requested directory')
print(root)
PY
}

stop_named_container() {
  local container_name="$1" expected_dir="$2"
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    python3 - "$container_name" "$expected_dir" "$image_id" <<'PY'
import json
import subprocess
import sys

name, fixture_dir, image_id = sys.argv[1:]
data = json.loads(subprocess.check_output(['docker', 'container', 'inspect', name], text=True))[0]
labels = data.get('Config', {}).get('Labels') or {}
if (data.get('Image') != image_id or
        labels.get('org.cicada.fixture') != 'client-group-key' or
        labels.get('org.cicada.fixture.dir') != fixture_dir):
    raise SystemExit('BLOCKED: refusing to stop a container not owned by this fixture')
PY
    docker stop --time 10 "$container_name" >/dev/null
  fi
}

start_hub() {
  docker run --rm -d --name "$hub_container" \
    --label 'org.cicada.fixture=client-group-key' \
    --label "org.cicada.fixture.dir=$fixture_dir" \
    -p '127.0.0.1::8787' \
    --env-file "$fixture_dir/hub.env" \
    -v "$fixture_dir/state:/state" \
    -v "$fixture_dir/workspace:/workspace" \
    -v "$fixture_dir/owner-public:/fixture-owner-public:ro" \
    "$image_id" serve --host 0.0.0.0 --port 8787 >/dev/null
  hub_port="$(docker port "$hub_container" 8787/tcp | python3 -c 'import sys; print(sys.stdin.read().strip().rsplit(":", 1)[-1])')"
  hub_url="http://127.0.0.1:${hub_port}"
  python3 - "$hub_url" <<'PY'
import sys
import time
import urllib.error
import urllib.request

base = sys.argv[1]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for attempt in range(60):
    try:
        with opener.open(base + '/healthz', timeout=2) as response:
            if response.status == 200:
                raise SystemExit(0)
    except (OSError, urllib.error.URLError):
        time.sleep(0.5)
raise SystemExit('BLOCKED: fixed-image Hub did not become healthy')
PY
}

record_command() {
  printf '%s\texit=%s\n' "$1" "$2" >>"$fixture_dir/commands.tsv"
}

start_fixture() {
  local tmp_root suffix host_uid host_gid
  local owner_key_id owner_id node_id node_agent_exit hub_id control_key_id expires_at
  local image_json image_arch host_arch binary_sha256
  tmp_root="$(real_tmp_root)"
  [[ "$(uname -s)" == Linux ]] || {
    printf 'BLOCKED: this disposable fixture requires Linux Docker host networking for local Node enrollment\n' >&2
    return 2
  }
  for command_name in docker python3 sha256sum; do
    command -v "$command_name" >/dev/null 2>&1 || {
      printf 'BLOCKED: required command unavailable: %s\n' "$command_name" >&2
      return 2
    }
  done
  docker info >/dev/null 2>&1 || {
    printf 'BLOCKED: Docker daemon unavailable\n' >&2
    return 2
  }
  image_json="$(docker image inspect "$image_id" 2>/dev/null)" || {
    printf 'BLOCKED: required fixed Hub image is not present locally: %s\n' "$image_id" >&2
    return 2
  }
  readarray -t image_fields < <(python3 -c 'import json,sys; d=json.loads(sys.stdin.read())[0]; l=d.get("Config",{}).get("Labels",{}); print(d.get("Id","")); print(l.get("org.opencontainers.image.revision","")); print(l.get("org.cicada.build.dirty","")); print(l.get("org.cicada.client-catalog.sha256","")); print(d.get("Architecture",""))' <<<"$image_json")
  [[ "${image_fields[0]:-}" == "$image_id" &&
     "${image_fields[1]:-}" == "$expected_revision" &&
     "${image_fields[2]:-}" == false &&
     "${image_fields[3]:-}" == "$expected_catalog" ]] || {
    printf 'BLOCKED: local image metadata does not match the fixed client target\n' >&2
    return 2
  }
  image_arch="${image_fields[4]}"
  host_arch="$(uname -m)"
  case "$host_arch:$image_arch" in
    x86_64:amd64|aarch64:arm64) ;;
    *)
      printf 'BLOCKED: fixed image architecture %s is not native to host architecture %s\n' "$image_arch" "$host_arch" >&2
      return 2
      ;;
  esac

  # The Node's native Join socket lives beneath this directory. Keep both
  # the fixture path and Node ID short enough for Linux's Unix socket limit.
  fixture_dir="$(mktemp -d "${tmp_root}/cgk.XXXXXXXX")"
  trap 'start_failure_cleanup "$?"' EXIT
  chmod 0700 "$fixture_dir"
  suffix="$(basename "$fixture_dir" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')"
  hub_container="cicada-cgk-${suffix}-hub"
  extract_name="cicada-cgk-${suffix}-extract"
  owner_id="client_test_owner_${suffix}"
  node_id="cgk-${suffix}"
  local join_socket="$fixture_dir/node-state/nodes/node-$node_id/join.sock"
  if (( ${#join_socket} >= 104 )); then
    printf 'BLOCKED: fixture native Join socket path is too long: %s bytes\n' "${#join_socket}" >&2
    return 2
  fi
  mkdir -m 0700 "$fixture_dir/state" "$fixture_dir/workspace" \
    "$fixture_dir/owner-private" "$fixture_dir/owner-public" \
    "$fixture_dir/node-state" "$fixture_dir/bin"
  python3 - "$fixture_dir" "$marker_name" "$hub_container" "$image_id" "$expected_revision" "$expected_catalog" "$owner_id" "$node_id" <<'PY'
from pathlib import Path
import json
import secrets
import sys

root = Path(sys.argv[1])
marker_name, hub, image, revision, catalog, owner, node = sys.argv[2:]
(root / marker_name).write_text(json.dumps({
    'schema': 'cicada.client-group-key-fixture.v1',
    'fixture_dir': str(root.resolve()),
    'hub_container': hub,
    'image_id': image,
    'source_revision': revision,
    'catalog_sha256': catalog,
}, sort_keys=True) + '\n')
(root / 'hub.env').write_text('CICADA_API_TOKEN=' + secrets.token_hex(32) + '\n')
(root / 'owner-id.txt').write_text(owner + '\n')
(root / 'node-id.txt').write_text(node + '\n')
(root / 'commands.tsv').write_text('')
(root / 'state' / '.cicada-disposable-client-group-key-fixture').write_text('synthetic /tmp fixture\n')
PY
  chmod 0600 "$fixture_dir/$marker_name" "$fixture_dir/hub.env" \
    "$fixture_dir/owner-id.txt" "$fixture_dir/node-id.txt" "$fixture_dir/commands.tsv"

  extract_id="$(docker create --name "$extract_name" "$image_id")"
  record_command "docker create fixed image for /usr/local/bin/cicada extraction" 0
  docker cp "$extract_id:/usr/local/bin/cicada" "$fixture_dir/bin/cicada" >/dev/null
  record_command "docker cp fixed-image cicada binary into /tmp fixture" 0
  docker container rm "$extract_id" >/dev/null
  record_command "docker container rm temporary extraction container" 0
  chmod 0755 "$fixture_dir/bin/cicada"
  "$fixture_dir/bin/cicada" version >"$fixture_dir/version.txt"
  record_command "fixed-image cicada version" 0
  binary_sha256="$(sha256sum "$fixture_dir/bin/cicada" | awk '{print $1}')"

  host_uid="$(id -u)"
  host_gid="$(id -g)"
  "$fixture_dir/bin/cicada" owner-key generate \
    --private "$fixture_dir/owner-private/owner-private.json" \
    --public "$fixture_dir/owner-public/owner-public.json" \
    >"$fixture_dir/keygen-result.json"
  record_command "cicada owner-key generate (offline; private file stays outside Hub mount)" 0
  owner_key_id="$(python3 - "$fixture_dir/keygen-result.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding='utf-8'))['key_id'])
PY
)"
  python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import os
import sys
root = Path(sys.argv[1])
private = root / 'owner-private' / 'owner-private.json'
public = root / 'owner-public' / 'owner-public.json'
if not private.is_file() or private.is_symlink() or private.stat().st_mode & 0o777 != 0o600:
    raise SystemExit('BLOCKED: synthetic Owner private key file is not a regular 0600 file')
if not public.is_file() or public.is_symlink():
    raise SystemExit('BLOCKED: synthetic Owner public identity file is missing')
(root / 'keygen-result.json').unlink()
PY

  start_hub
  record_command "docker run fixed Hub image and wait for /healthz" 0
  python3 - "$hub_url" "$fixture_dir/hub-identity.json" "$expected_revision" "$expected_catalog" "$image_id" <<'PY'
import json
import sys
import urllib.request

base, destination, revision, catalog, image_id = sys.argv[1:]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(base + '/healthz', timeout=5) as response:
    health = json.load(response)
with opener.open(base + '/v2/client/capabilities', timeout=5) as response:
    capabilities = json.load(response)
with opener.open(base + '/v2/client/identity', timeout=5) as response:
    identity = json.load(response)
if health.get('status') != 'ok' or health.get('revision') != revision or health.get('dirty') is not False:
    raise SystemExit('BLOCKED: fixed Hub health provenance did not match')
if health.get('catalog_sha256') != catalog or capabilities.get('catalog_sha256') != catalog:
    raise SystemExit('BLOCKED: fixed Hub catalog digest did not match')
if capabilities.get('status') != 'partial' or identity.get('contract') != 'android-hub-v1':
    raise SystemExit('BLOCKED: fixed Hub Client endpoints did not match expected contract')
with open(destination, 'x', encoding='utf-8') as output:
    json.dump({'hub_id': identity['hub_id'], 'control_public_identity': identity['control_public_identity'],
               'control_key_version': identity['control_key_version'], 'contract': identity['contract'],
               'contract_revision': capabilities.get('contract_revision'), 'catalog_sha256': catalog,
               'source_revision': revision, 'image_id': image_id}, output, indent=2, sort_keys=True)
    output.write('\n')
PY
  record_command "GET /healthz, /v2/client/capabilities, /v2/client/identity provenance check" 0
  chmod 0600 "$fixture_dir/hub-identity.json"
  hub_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hub_id"])' "$fixture_dir/hub-identity.json")"
  control_key_id="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["control_public_identity"]["id"])' "$fixture_dir/hub-identity.json")"

  docker stop --time 10 "$hub_container" >/dev/null
  record_command "docker stop Hub before offline owner registration" 0
  docker run --rm --user "${host_uid}:${host_gid}" \
    -v "$fixture_dir/state:/state" \
    -v "$fixture_dir/owner-public:/fixture-owner-public:ro" \
    "$image_id" owner-key register --db /state/cicada.sqlite3 \
      --owner-id "$owner_id" \
      --public /fixture-owner-public/owner-public.json \
      --expect-key-id "$owner_key_id" >"$fixture_dir/owner-registration.json"
  record_command "fixed-image cicada owner-key register against stopped disposable Hub DB" 0
  chmod 0600 "$fixture_dir/owner-registration.json"

  start_hub
  record_command "restart fixed Hub after offline Owner registration" 0
  python3 - "$hub_url" "$fixture_dir/hub-identity.json" <<'PY'
import json
import sys
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(sys.argv[1] + '/v2/client/identity', timeout=5) as response:
    current = json.load(response)
saved = json.load(open(sys.argv[2], encoding='utf-8'))
if current.get('hub_id') != saved.get('hub_id') or current.get('control_public_identity') != saved.get('control_public_identity'):
    raise SystemExit('BLOCKED: Hub identity changed while registering synthetic Owner')
PY
  record_command "Hub identity stable across offline Owner registration" 0

  python3 - "$fixture_dir/node-bootstrap-started.txt" <<'PY'
from datetime import datetime, timezone
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z') + '\n')
PY
  set +e
  "$fixture_dir/bin/cicada" machine agent --id "$node_id" \
    --name 'Disposable Client Group-key Node' \
    --control-url "$hub_url" --state-dir "$fixture_dir/node-state" --once \
    >"$fixture_dir/node-bootstrap.raw" 2>&1
  node_agent_exit=$?
  set -e
  record_command "cicada machine agent --once (expected pending-owner-confirmation exit 1)" "$node_agent_exit"
  expires_at="$(python3 - "$fixture_dir/node-bootstrap.raw" "$fixture_dir/node-bootstrap-started.txt" "$fixture_dir/node-device-code.txt" <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys

log_path, started_path, code_path = map(Path, sys.argv[1:])
text = log_path.read_text(errors='replace')
match = re.search(r'Device code: ([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}) ', text)
if not match:
    raise SystemExit('BLOCKED: Node bootstrap did not produce a formatted one-time device code')
code_path.write_text(match.group(1) + '\n')
code_path.chmod(0o600)
log_path.unlink()
started = datetime.fromisoformat(started_path.read_text().strip().replace('Z', '+00:00'))
print((started + timedelta(minutes=10)).replace(microsecond=0).isoformat().replace('+00:00', 'Z'))
PY
)"
  [[ "$node_agent_exit" -eq 1 ]] || {
    printf 'BLOCKED: fresh Node bootstrap returned unexpected exit %s; fixture retained at %s\n' "$node_agent_exit" "$fixture_dir" >&2
    return 2
  }

  python3 - "$fixture_dir" "$image_id" "$hub_url" "$hub_id" "$control_key_id" \
    "$owner_id" "$owner_key_id" "$node_id" "$binary_sha256" "$expires_at" <<'PY'
from pathlib import Path
import json
import sys

root = Path(sys.argv[1])
image, hub_url, hub_id, control_key, owner, owner_key, node, binary, expires = sys.argv[2:]
data = {
    'schema': 'cicada.client-group-key-fixture-result.v1',
    'status': 'PREPARED_AWAITING_CLIENT_AND_NATIVE_JOIN',
    'hub': {'image_id': image, 'source_revision': '967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a',
            'contract_revision': 'client-hub-v1.2.1', 'catalog_sha256': '25c3d7f585b1811781cb46669a09e2e08ab8c58765a7b9318145cea5bbce4df9',
            'url': hub_url, 'hub_id': hub_id, 'control_key_id': control_key},
    'owner': {'owner_id': owner, 'owner_key_id': owner_key,
              'private_key_path': str(root / 'owner-private' / 'owner-private.json'),
              'private_key_mode': '0600', 'private_key_mounted_into_hub': False},
    'node': {'node_id': node, 'state_dir': str(root / 'node-state'),
             'credential_stays_on_node': True, 'bootstrap_exit_code': 1,
             'state': 'AWAITING_OWNER_CONFIRMATION',
             'device_code_file': str(root / 'node-device-code.txt'), 'device_code_expires_at': expires},
    'fixed_image_cicada_binary_sha256': binary,
    'android_owner_enrollment': 'NOT_RUN', 'android_group_create_and_node_confirm': 'NOT_RUN',
    'native_codex_join_and_leased_endpoint': 'NOT_RUN', 'group_key_manifest_grant_status': 'NOT_RUN',
    'physical_android': 'NOT_RUN', 'public_https': 'NOT_RUN',
}
path = root / 'fixture-result.json'
path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
path.chmod(0o600)
PY
  chmod 0600 "$fixture_dir/commands.tsv" "$fixture_dir/node-device-code.txt" "$fixture_dir/fixture-result.json"
  cat "$fixture_dir/commands.tsv"
  printf 'PASS: fixed v1.2.1 Hub prepared in disposable state.\n'
  printf 'Hub URL: %s\nHub ID: %s\nControl key ID: %s\n' "$hub_url" "$hub_id" "$control_key_id"
  printf 'Synthetic Owner ID: %s\nOwner key ID: %s\nOwner private key file (outside Hub and APK): %s/owner-private/owner-private.json\n' \
    "$owner_id" "$owner_key_id" "$fixture_dir"
  printf 'Synthetic Node ID: %s\nNode device code file (0600): %s/node-device-code.txt\nDevice code expires at: %s\n' \
    "$node_id" "$fixture_dir" "$expires_at"
  printf 'Node credential directory (Node only; never copy to Android): %s/node-state\n' "$fixture_dir"
  printf 'Fixture result: %s/fixture-result.json\n' "$fixture_dir"
  printf 'NOT_RUN: Android owner enrollment, Android Node confirmation/Group create, native Codex Join, leased Endpoint, group.key_manifest/grant/status, physical Android, public HTTPS.\n'
  printf 'Teardown: %s stop %s\n' "$repo_root/scripts/client-group-key-fixture.sh" "$fixture_dir"
  trap - EXIT
}

start_failure_cleanup() {
  local exit_code="${1:-1}"
  if [[ -n "${hub_container:-}" ]] && docker container inspect "$hub_container" >/dev/null 2>&1; then
    if ! stop_named_container "$hub_container" "$fixture_dir" >/dev/null 2>&1; then
      printf 'BLOCKED: refusing to stop an unrelated container named %s\n' "$hub_container" >&2
    fi
  fi
  if [[ -n "$extract_id" ]] && docker container inspect "$extract_id" >/dev/null 2>&1; then
    docker container rm "$extract_id" >/dev/null 2>&1 || true
  fi
  if [[ -n "${fixture_dir:-}" && -d "$fixture_dir" ]]; then
    python3 - "$fixture_dir" <<'PY'
from pathlib import Path
import os
import shutil
import sys
root = Path(sys.argv[1]).resolve(strict=True)
tmp = Path('/tmp').resolve(strict=True)
if os.path.commonpath((str(root), str(tmp))) != str(tmp) or root == tmp:
    raise SystemExit('BLOCKED: refusing to clean a path outside real /tmp')
shutil.rmtree(root)
PY
    printf 'FAIL: preparation stopped with exit %s; partial Hub/state/secrets were cleaned from %s\n' "$exit_code" "$fixture_dir" >&2
  fi
  return "$exit_code"
}

stop_fixture() {
  local requested root hub expected_hub
  requested="$1"
  root="$(validate_fixture_dir "$requested")"
  hub="$(python3 - "$root" "$marker_name" <<'PY'
import json
from pathlib import Path
import sys
print(json.loads((Path(sys.argv[1]) / sys.argv[2]).read_text())['hub_container'])
PY
)"
  expected_hub="cicada-cgk-$(basename "$root" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')-hub"
  [[ "$hub" == "$expected_hub" ]] || {
    printf 'BLOCKED: fixture marker container name does not match directory\n' >&2
    return 2
  }
  stop_named_container "$hub" "$root"
  python3 - "$root" <<'PY'
from pathlib import Path
import os
import shutil
import sys
root = Path(sys.argv[1]).resolve(strict=True)
tmp = Path('/tmp').resolve(strict=True)
if os.path.commonpath((str(root), str(tmp))) != str(tmp) or root == tmp:
    raise SystemExit('BLOCKED: refusing to remove a path outside real /tmp')
shutil.rmtree(root)
PY
  printf 'PASS: disposable Hub/Node state and synthetic keys removed from %s\n' "$root"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi
case "$1" in
  start)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    start_fixture
    ;;
  stop)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    stop_fixture "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
