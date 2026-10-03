#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf 'usage: %s [--image IMAGE] [--interop-test-image IMAGE] [--metadata-file PATH]\n' "$0" >&2
  printf '       %s --source-info-only --metadata-file PATH\n' "$0" >&2
  printf '       optional: --transport pqtls --pqtls-stage ACCEPTED_PREFIX (linux/amd64 only)\n' >&2
  exit 2
}

image_name="${CICADA_HUB_IMAGE:-cicada-codex:hub-dev}"
test_image_name=""
metadata_file=""
source_info_only=false
transport=standard
pq_stage=''
while (($#)); do
  case "$1" in
    --image)
      (($# >= 2)) || usage
      image_name="$2"
      shift 2
      ;;
    --interop-test-image)
      (($# >= 2)) || usage
      test_image_name="$2"
      shift 2
      ;;
    --metadata-file)
      (($# >= 2)) || usage
      metadata_file="$2"
      shift 2
      ;;
    --source-info-only)
      source_info_only=true
      shift
      ;;
    --transport)
      (($# >= 2)) || usage
      transport="$2"; shift 2
      ;;
    --pqtls-stage)
      (($# >= 2)) || usage
      pq_stage="$2"; shift 2
      ;;
    *)
      usage
      ;;
  esac
done
[[ "$transport" == standard || "$transport" == pqtls ]] || usage
[[ "$transport" == pqtls || -z "$pq_stage" ]] || usage

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
dockerfile="${repo_root}/docker/Dockerfile.hub"
dockerfile_relative="docker/Dockerfile.hub"
inventory_args=()
verify_args=()
variant_build_args=()
if [[ "$transport" == pqtls ]]; then
  [[ -n "$pq_stage" ]] || usage
  pq_stage="$(cd "$pq_stage" && pwd -P)"
  dockerfile_relative="docker/Dockerfile.hub-pqtls"
  dockerfile="$repo_root/$dockerfile_relative"
  inventory_args=(--transport pqtls --pqtls-stage "$pq_stage")
  verify_args=(--pqtls-stage "$pq_stage")
  variant_build_args=(--platform linux/amd64 --build-context "pqtls-stage=$pq_stage")
fi
catalog_file="${repo_root}/cicada-go/internal/clientcontract/catalog.json"
inventory_helper="${repo_root}/scripts/hub-build-input-inventory.py"

[[ "$source_info_only" != true || -n "$metadata_file" ]] || usage
required_commands=(git python3 sha256sum)
if [[ "$source_info_only" != true ]]; then
  required_commands+=(docker)
fi
for command_name in "${required_commands[@]}"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'build-hub-image: required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
[[ -f "$dockerfile" && -f "$catalog_file" && -f "$inventory_helper" ]] || {
  printf 'build-hub-image: Dockerfile, embedded client contract catalog, or inventory helper is missing\n' >&2
  exit 1
}

inventory_temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/cicada-hub-inputs.XXXXXXXX")"
chmod 0700 "$inventory_temp_dir"
source_inventory_file="${inventory_temp_dir}/inventory.json"
trap 'rm -rf -- "$inventory_temp_dir"' EXIT

if [[ -n "$metadata_file" ]]; then
  python3 - "$repo_root" "$metadata_file" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
destination = pathlib.Path(sys.argv[2]).resolve()
try:
    relative = destination.relative_to(root).as_posix()
except ValueError:
    raise SystemExit(0)
if relative != ".cicada-data" and not relative.startswith(".cicada-data/"):
    raise SystemExit("build-hub-image: metadata output must be outside the checkout or under ignored .cicada-data")
PY
fi

revision="$(git -C "$repo_root" rev-parse HEAD)"
read_dirty_state() {
  local status
  if ! status="$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all)"; then
    printf 'build-hub-image: unable to inspect source tree status\n' >&2
    return 1
  fi
  if [[ -z "$status" ]]; then
    printf 'false'
  else
    printf 'true'
  fi
}

dirty="$(read_dirty_state)"

compute_source_fingerprint() {
  if [[ "$transport" == pqtls ]]; then
    python3 "$inventory_helper" capture --root "$repo_root" "${inventory_args[@]}" --fingerprint-only
    return
  fi
  python3 - "$repo_root" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys

root = os.fsencode(sys.argv[1])
paths = subprocess.run(
    [b"git", b"-C", root, b"ls-files", b"--cached", b"--others", b"--exclude-standard", b"-z", b"--", b"cicada-go", b"docker/Dockerfile.hub", b".dockerignore", b"scripts/build-web-panel.sh", b"scripts/write-web-panel-manifest.py", b"scripts/build-hub-image.sh", b".github/workflows/release.yml"],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
).stdout.split(b"\0")
digest = hashlib.sha256(b"cicada-hub-build-inputs-v4\0")
for relative in sorted(path for path in set(paths) if path):
    absolute = os.path.join(root, relative)
    try:
        metadata = os.lstat(absolute)
    except FileNotFoundError:
        continue
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(stat.S_IMODE(metadata.st_mode).to_bytes(4, "big"))
    if stat.S_ISLNK(metadata.st_mode):
        content = os.fsencode(os.readlink(absolute))
    elif stat.S_ISREG(metadata.st_mode):
        with open(absolute, "rb") as source:
            content = source.read()
    else:
        content = b""
    digest.update(hashlib.sha256(content).digest())
print(digest.hexdigest())
PY
}

capture_source_snapshot() {
  local first_fingerprint second_fingerprint inventory_fingerprint
  first_fingerprint="$(compute_source_fingerprint)"
  if ! python3 "$inventory_helper" capture --root "$repo_root" "${inventory_args[@]}" --output "$source_inventory_file"; then
    printf 'build-hub-image: failed to capture Hub build-input inventory\n' >&2
    return 1
  fi
  second_fingerprint="$(compute_source_fingerprint)"
  inventory_fingerprint="$(python3 - "$source_inventory_file" "$transport" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["fingerprint" if sys.argv[2] == "pqtls" else "source_fingerprint_v4"]["sha256"])
PY
  )"
  if [[ "$first_fingerprint" != "$second_fingerprint" || "$second_fingerprint" != "$inventory_fingerprint" ]]; then
    printf 'build-hub-image: source changed or v4 inventory recomputation disagrees\n' >&2
    return 1
  fi
  if ! python3 "$inventory_helper" verify --root "$repo_root" "${verify_args[@]}" --expected "$source_inventory_file"; then
    printf 'build-hub-image: source changed while build metadata was being collected\n' >&2
    return 1
  fi
  source_fingerprint="$second_fingerprint"
}

source_fingerprint=""
capture_source_snapshot
catalog_sha256="$(sha256sum "$catalog_file" | cut -d ' ' -f 1)"

verify_source_snapshot() {
  local current_revision current_dirty current_fingerprint current_catalog_sha256 inventory_fingerprint
  current_revision="$(git -C "$repo_root" rev-parse HEAD)"
  if ! current_dirty="$(read_dirty_state)"; then
    return 1
  fi
  current_fingerprint="$(compute_source_fingerprint)"
  current_catalog_sha256="$(sha256sum "$catalog_file" | cut -d ' ' -f 1)"
  inventory_fingerprint="$(python3 - "$source_inventory_file" "$transport" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["fingerprint" if sys.argv[2] == "pqtls" else "source_fingerprint_v4"]["sha256"])
PY
  )"
  python3 "$inventory_helper" verify --root "$repo_root" "${verify_args[@]}" --expected "$source_inventory_file" >/dev/null 2>&1 || return 1
  [[ "$current_revision" == "$revision" && "$current_dirty" == "$dirty" &&
     "$current_fingerprint" == "$source_fingerprint" && "$current_fingerprint" == "$inventory_fingerprint" &&
     "$current_catalog_sha256" == "$catalog_sha256" ]]
}

build_version="${CICADA_BUILD_VERSION:-0.1.0-dev}"
webcrypto_manifest_sha256="${CICADA_BUILD_WEBCRYPTO_MANIFEST_SHA256:-unknown}"
[[ "$build_version" =~ ^[0-9A-Za-z.+-]+$ ]] || {
  printf 'build-hub-image: invalid CICADA_BUILD_VERSION\n' >&2
  exit 2
}
if [[ "$webcrypto_manifest_sha256" != unknown && ! "$webcrypto_manifest_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'build-hub-image: invalid WebCrypto manifest SHA-256\n' >&2
  exit 2
fi

if [[ "$source_info_only" == true ]]; then
  if ! verify_source_snapshot; then
    printf 'build-hub-image: source changed while source metadata was being collected\n' >&2
    exit 1
  fi
  python3 - "$metadata_file" "$source_inventory_file" "$revision" "$dirty" "$source_fingerprint" "$catalog_sha256" "$transport" "$dockerfile_relative" <<'PY'
import json
import os
import sys
import tempfile

path, inventory_path, revision, dirty, source_fingerprint, catalog_sha256, transport, dockerfile = sys.argv[1:]
with open(inventory_path, encoding="utf-8") as source:
    input_inventory = json.load(source)
result = {
    "schema_version": "cicada.hub-build-source.v1",
    "transport_variant": transport,
    "pqtls_available": transport == "pqtls",
    "dockerfile": dockerfile,
    "source": {
        "revision": revision,
        "dirty": dirty == "true",
        "source_fingerprint": source_fingerprint,
        "catalog_sha256": catalog_sha256,
        "input_inventory": input_inventory,
    },
}
directory = os.path.dirname(os.path.abspath(path))
os.makedirs(directory, mode=0o700, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".hub-source-", dir=directory)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
  printf 'Hub source revision: %s\nHub source dirty: %s\nHub source fingerprint: %s\nCatalog SHA-256: %s\n' \
    "$revision" "$dirty" "$source_fingerprint" "$catalog_sha256"
  exit 0
fi

build_args=(
  --build-arg "CICADA_UID=${CICADA_UID:-$(id -u)}"
  --build-arg "CICADA_GID=${CICADA_GID:-$(id -g)}"
  --build-arg "CICADA_BUILD_REVISION=${revision}"
  --build-arg "CICADA_BUILD_DIRTY=${dirty}"
  --build-arg "CICADA_BUILD_SOURCE_FINGERPRINT=${source_fingerprint}"
  --build-arg "CICADA_BUILD_CATALOG_SHA256=${catalog_sha256}"
  --build-arg "CICADA_BUILD_VERSION=${build_version}"
  --build-arg "CICADA_BUILD_WEBCRYPTO_MANIFEST_SHA256=${webcrypto_manifest_sha256}"
)

add_proxy_args() {
  local http_proxy_value=""
  local https_proxy_value=""
  local all_proxy_value=""
  local no_proxy_value=""

  if [[ ${CICADA_BUILD_PROXY+x} ]]; then
    if [[ -n "$CICADA_BUILD_PROXY" ]]; then
      http_proxy_value="$CICADA_BUILD_PROXY"
      https_proxy_value="$CICADA_BUILD_PROXY"
    fi
  else
    http_proxy_value="${HTTP_PROXY:-${http_proxy:-}}"
    https_proxy_value="${HTTPS_PROXY:-${https_proxy:-}}"
    all_proxy_value="${ALL_PROXY:-${all_proxy:-}}"
    no_proxy_value="${NO_PROXY:-${no_proxy:-}}"
    if [[ -z "$http_proxy_value$https_proxy_value$all_proxy_value" ]] && \
      python3 - <<'PY' >/dev/null 2>&1
import socket
with socket.create_connection(("127.0.0.1", 7890), timeout=0.2):
    pass
PY
    then
      http_proxy_value="http://127.0.0.1:7890"
      https_proxy_value="$http_proxy_value"
    fi
  fi

  [[ -z "$http_proxy_value" ]] || build_args+=(--build-arg "HTTP_PROXY=${http_proxy_value}")
  [[ -z "$https_proxy_value" ]] || build_args+=(--build-arg "HTTPS_PROXY=${https_proxy_value}")
  [[ -z "$all_proxy_value" ]] || build_args+=(--build-arg "ALL_PROXY=${all_proxy_value}")
  [[ -z "$no_proxy_value" ]] || build_args+=(--build-arg "NO_PROXY=${no_proxy_value}")
}
add_proxy_args

build_log="$(mktemp "${TMPDIR:-/tmp}/cicada-hub-build.XXXXXXXX")"
image_ids="$(mktemp -d "${TMPDIR:-/tmp}/cicada-hub-images.XXXXXXXX")"
chmod 0600 "$build_log"
cleanup() { rm -f "$build_log"; rm -rf -- "$image_ids" "$inventory_temp_dir"; }
trap cleanup EXIT

build_target() {
  local target="$1"
  local tag="$2"
  if ! docker build --quiet --network=host --target "$target" --iidfile "$image_ids/$target" \
    "${variant_build_args[@]}" "${build_args[@]}" -f "$dockerfile" -t "$tag" "$repo_root" \
    >"$build_log" 2>&1; then
    if ! verify_source_snapshot; then
      printf 'build-hub-image: source changed during the Docker build; rerun from a stable checkout\n' >&2
      return 1
    fi
    local diagnostic
    diagnostic="${TMPDIR:-/tmp}/cicada-hub-build-${target}-$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
    cp "$build_log" "$diagnostic"
    chmod 0600 "$diagnostic"
    printf 'build-hub-image: Docker build failed for target %s; private diagnostics saved to %s\n' "$target" "$diagnostic" >&2
    return 1
  fi
}

build_target hub-runtime "$image_name"
if [[ -n "$test_image_name" ]]; then
  build_target interop-test "$test_image_name"
fi
if ! verify_source_snapshot; then
  printf 'build-hub-image: source changed during the Docker build; rerun from a stable checkout\n' >&2
  exit 1
fi

image_id="$(cat "$image_ids/hub-runtime")"
test_image_id=""
if [[ -n "$test_image_name" ]]; then
  test_image_id="$(cat "$image_ids/interop-test")"
fi
if [[ -n "$metadata_file" ]]; then
  python3 - "$metadata_file" "$source_inventory_file" "$image_name" "$image_id" "$revision" "$dirty" "$source_fingerprint" "$catalog_sha256" "$test_image_name" "$test_image_id" "$transport" "$dockerfile_relative" <<'PY'
import json
import os
import sys
import tempfile

path, inventory_path, reference, image_id, revision, dirty, source_fingerprint, catalog_sha256, test_reference, test_id, transport, dockerfile = sys.argv[1:]
with open(inventory_path, encoding="utf-8") as source:
    input_inventory = json.load(source)
result = {
    "schema_version": "cicada.hub-build.v1",
    "transport_variant": transport,
    "pqtls_available": transport == "pqtls",
    "source": {
        "revision": revision,
        "dirty": dirty == "true",
        "source_fingerprint": source_fingerprint,
        "catalog_sha256": catalog_sha256,
        "input_inventory": input_inventory,
    },
    "image": {
        "reference": reference,
        "id": image_id,
        "dockerfile": dockerfile,
    },
}
if test_id:
    result["test_image"] = {"reference": test_reference, "id": test_id}
directory = os.path.dirname(os.path.abspath(path))
os.makedirs(directory, mode=0o700, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".hub-build-", dir=directory)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(result, output, sort_keys=True, indent=2)
        output.write("\n")
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
fi

printf 'Built Hub image: %s (%s)\n' "$image_name" "$image_id"
printf 'Source revision: %s\n' "$revision"
printf 'Source dirty: %s\n' "$dirty"
printf 'Source fingerprint: %s\n' "$source_fingerprint"
printf 'Catalog SHA-256: %s\n' "$catalog_sha256"
