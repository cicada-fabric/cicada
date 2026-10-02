#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'usage: %s VERSION [OUTPUT_DIR] [--transport standard|pqtls] [--pqtls-stage PREFIX]\n' "$0" >&2
  printf 'builds checksummed CICADA binaries with embedded Hub WebCrypto assets and source provenance\n' >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
version="$1"
shift
out_dir=dist
if (($#)) && [[ "$1" != --* ]]; then out_dir="$1"; shift; fi
transport=standard
pq_stage=''
while (($#)); do
  case "$1" in
    --transport) (($# >= 2)) || usage; transport="$2"; shift 2 ;;
    --pqtls-stage) (($# >= 2)) || usage; pq_stage="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$transport" == standard || "$transport" == pqtls ]] || usage
[[ "$transport" == pqtls || -z "$pq_stage" ]] || usage
[[ "$version" =~ ^[0-9A-Za-z.-]+$ ]] || { printf 'build-release: invalid version: %s\n' "$version" >&2; exit 2; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
for command_name in go git python3 gzip sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'build-release: %s is required\n' "$command_name" >&2
    exit 1
  }
done
[[ -f "$repo_root/cicada-go/go.mod" ]] || { printf 'build-release: CICADA Go source is missing\n' >&2; exit 1; }
go_version="$(go version)"
[[ "$(awk '{print $3}' <<<"$go_version")" == go1.27.1 ]] || {
  printf 'build-release: Go 1.27.1 is required to match the Hub WebCrypto runtime\n' >&2
  exit 1
}
if [[ "$transport" == pqtls ]]; then
  [[ -n "$pq_stage" && "${CGO_ENABLED:-1}" == 1 && "${GOOS:-linux}" == linux && "${GOARCH:-amd64}" == amd64 ]] || {
    printf 'build-release: PQ requires explicit accepted stage, CGO1 and linux/amd64\n' >&2; exit 1;
  }
  [[ "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" == linux/amd64 ]] || {
    printf 'build-release: PQ requires a native Linux amd64 glibc build host\n' >&2; exit 1;
  }
  pq_stage="$(cd "$pq_stage" && pwd -P)"
  python3 "$repo_root/scripts/hub-build-input-inventory.py" runtime --pqtls-stage "$pq_stage" >/dev/null
fi

compute_source_fingerprint() {
  if [[ "$transport" == pqtls ]]; then
    python3 "$repo_root/scripts/hub-build-input-inventory.py" capture --root "$repo_root" \
      --transport pqtls --pqtls-stage "$pq_stage" --fingerprint-only
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
    [b"git", b"-C", root, b"ls-files", b"--cached", b"--others", b"--exclude-standard", b"-z", b"--",
     b"cicada-go", b"scripts/build-release.sh", b"scripts/hub-build-input-inventory.py", b"scripts/write-web-panel-manifest.py", b".github/workflows/release.yml"],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
).stdout.split(b"\0")
digest = hashlib.sha256(b"cicada-binary-release-inputs-v2\0")
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

compute_dirty() {
  if [[ "$transport" == pqtls ]]; then
    python3 "$repo_root/scripts/hub-build-input-inventory.py" dirty --root "$repo_root"
    return
  fi
  if [[ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all -- \
      cicada-go scripts/build-release.sh scripts/hub-build-input-inventory.py scripts/write-web-panel-manifest.py .github/workflows/release.yml)" ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

revision="$(git -C "$repo_root" rev-parse HEAD)"
dirty="$(compute_dirty)"
source_fingerprint="$(compute_source_fingerprint)"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cicada-release.XXXXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
source_dir="$work_dir/source"
stage_dir="$work_dir/dist"
mkdir -p "$source_dir" "$stage_dir"
cp -a "$repo_root/cicada-go" "$source_dir/cicada-go"

# Go's embed FS is populated from ui/generated at compile time. Build these
# production assets in the disposable source copy so the checkout is untouched.
staged_generated="$source_dir/cicada-go/internal/server/ui/generated"
rm -rf -- "$staged_generated"
mkdir -p "$staged_generated"
raw_wasm="$work_dir/cicada-webcrypto.wasm"
(
  cd "$source_dir/cicada-go"
  CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -buildvcs=false \
    -o "$raw_wasm" ./cmd/cicada-webcrypto
)
goroot="$(go env GOROOT)"
wasm_exec="$goroot/lib/wasm/wasm_exec.js"
if [[ ! -f "$wasm_exec" ]]; then
  wasm_exec="$goroot/misc/wasm/wasm_exec.js"
fi
[[ -f "$wasm_exec" ]] || { printf 'build-release: Go wasm_exec.js is missing from GOROOT\n' >&2; exit 1; }
cp "$wasm_exec" "$staged_generated/wasm_exec.js"
gzip -n -9 -c "$raw_wasm" > "$staged_generated/cicada-webcrypto.wasm.gz"
python3 "$repo_root/scripts/write-web-panel-manifest.py" \
  "$staged_generated" "$go_version" "$raw_wasm"
wasm_manifest_sha256="$(sha256sum "$staged_generated/panel.manifest.json" | cut -d ' ' -f 1)"
catalog_sha256="$(sha256sum "$repo_root/cicada-go/internal/clientcontract/catalog.json" | cut -d ' ' -f 1)"

targets=(
  'linux amd64'
  'linux arm64'
  'darwin amd64'
  'darwin arm64'
  'windows amd64'
)
if [[ "$transport" == pqtls ]]; then
  package="$stage_dir/cicada-linux-amd64-pqtls"
  mkdir -p "$package/bin" "$package/lib" "$package/share/licenses/openssl"
  python3 "$repo_root/scripts/hub-build-input-inventory.py" capture --root "$repo_root" \
    --transport pqtls --pqtls-stage "$pq_stage" --output "$work_dir/pq-inputs.json"
  cgo_flags="$(python3 - "$pq_stage" <<'PY'
import shlex, sys
print(shlex.quote('-I' + sys.argv[1] + '/include'))
PY
)"
  cgo_link="$(python3 - "$pq_stage" <<'PY'
import shlex, sys
print(shlex.quote('-L' + sys.argv[1] + '/lib') + ' ' + shlex.quote('-Wl,-rpath,$ORIGIN/../lib'))
PY
)"
  (
    cd "$source_dir/cicada-go"
    CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CGO_CFLAGS="$cgo_flags" CGO_LDFLAGS="$cgo_link" \
      go build -trimpath -buildvcs=false -tags cicada_pqtls \
      -ldflags="-s -w -X github.com/cicada-ai/cicada/internal/buildinfo.Version=${version} -X github.com/cicada-ai/cicada/internal/buildinfo.Revision=${revision} -X github.com/cicada-ai/cicada/internal/buildinfo.Dirty=${dirty} -X github.com/cicada-ai/cicada/internal/buildinfo.SourceFingerprint=${source_fingerprint}" \
      -o "$package/bin/cicada" ./cmd/cicada
  )
  cp "$pq_stage/lib/libssl.so.3" "$pq_stage/lib/libcrypto.so.3" "$package/lib/"
  cp "$pq_stage/share/licenses/openssl/LICENSE.txt" "$package/share/licenses/openssl/"
  CGO_ENABLED=1 CGO_CFLAGS="$cgo_flags" CGO_LDFLAGS="$cgo_link" \
    python3 "$repo_root/scripts/hub-build-input-inventory.py" go-notices \
      --source "$source_dir/cicada-go" --destination "$package/share/licenses" --tags cicada_pqtls
  python3 - "$package" "$work_dir/pq-inputs.json" "$version" "$revision" "$dirty" "$wasm_manifest_sha256" "$catalog_sha256" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1]); inputs = json.loads(pathlib.Path(sys.argv[2]).read_text())
version, revision, dirty, wasm, catalog = sys.argv[3:]
metadata = {'schema_version': 'cicada.pqtls-distribution.v1', 'software_version': version,
            'source': {'revision': revision, 'dirty': dirty == 'true', 'source_fingerprint': inputs['fingerprint']['sha256'], 'input_inventory': inputs},
            'toolchain': 'go1.27.1', 'hub_webcrypto_manifest_sha256': wasm, 'catalog_sha256': catalog,
            'targets': ['linux/amd64'], 'transport_variant': 'pqtls', 'pqtls_available': True,
            'cgo_enabled': True, 'build_tag': 'cicada_pqtls', 'openssl_version': '3.5.9',
            'loader': {'interpreter': '/lib64/ld-linux-x86-64.so.2', 'runpath': '$ORIGIN/../lib', 'minimum_observed_glibc_symbol': '2.34'},
            'runtime': inputs['runtime']}
(root / 'BUILD-METADATA.json').write_text(json.dumps(metadata, sort_keys=True, indent=2) + '\n')
(root / 'README.txt').write_text('CICADA optional Linux amd64 pure-PQ transport package. Initially validated on Debian12/bookworm glibc; not Alpine/musl.\nKeep bin/cicada and sibling lib together. Verify SHA256SUMS before startup and clear ambient LD_LIBRARY_PATH/LD_PRELOAD. No global loader installation is required.\nHub: bin/cicada serve --node-pqtls-config /private/hub.json\nNode: CICADA_BINARY_PATH=<package>/bin/cicada CICADA_NODE_PQTLS_CONFIG=/private/node.json scripts/install-cicada-worker.sh\nCertificate approval and rotation are manual, TLS keys are independent, and current Store authority plus certificate validity fences remain enforced. No CA/OCSP/CRL service is bundled. Client/bootstrap uses the application frontdoor. No private keys or deployment fixtures are included.\n')
files = sorted(p for p in root.rglob('*') if p.is_file())
(root / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n' for p in files))
PY
  python3 "$repo_root/scripts/hub-build-input-inventory.py" verify --root "$repo_root" \
    --pqtls-stage "$pq_stage" --expected "$work_dir/pq-inputs.json"
  (cd "$stage_dir" && tar -czf cicada-linux-amd64-pqtls.tar.gz cicada-linux-amd64-pqtls)
  python3 - "$stage_dir" "$package" "$source_fingerprint" <<'PY'
import hashlib,json,pathlib,sys
stage, package = map(pathlib.Path,sys.argv[1:3])
receipt={'schema_version':'cicada.pqtls-package-build-receipt.v1','source_fingerprint':sys.argv[3],
         'archive_sha256':hashlib.sha256((stage/'cicada-linux-amd64-pqtls.tar.gz').read_bytes()).hexdigest(),
         'package_file_sha256':{p.relative_to(package).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in package.rglob('*') if p.is_file()}}
(stage/'PQ-BUILD-RECEIPT.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
PY
  rm -rf "$package"
  (cd "$stage_dir" && sha256sum cicada-linux-amd64-pqtls.tar.gz PQ-BUILD-RECEIPT.json > SHA256SUMS)
else
for target in "${targets[@]}"; do
  read -r os arch <<<"$target"
  suffix=''
  [[ "$os" == windows ]] && suffix='.exe'
  output="$stage_dir/cicada-${os}-${arch}${suffix}"
  printf 'building %s\n' "$(basename "$output")"
  (
    cd "$source_dir/cicada-go"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X github.com/cicada-ai/cicada/internal/buildinfo.Version=${version} -X github.com/cicada-ai/cicada/internal/buildinfo.Revision=${revision} -X github.com/cicada-ai/cicada/internal/buildinfo.Dirty=${dirty} -X github.com/cicada-ai/cicada/internal/buildinfo.SourceFingerprint=${source_fingerprint}" \
      -o "$output" ./cmd/cicada
  )
done

CGO_ENABLED=0 python3 "$repo_root/scripts/hub-build-input-inventory.py" go-notices \
  --source "$source_dir/cicada-go" --destination "$work_dir/standard-notices" \
  --targets linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64
(cd "$work_dir" && tar -czf "$stage_dir/LICENSE-NOTICES.tar.gz" standard-notices)

python3 - "$stage_dir/BUILD-METADATA.json" "$version" "$revision" "$dirty" "$source_fingerprint" "$go_version" "$wasm_manifest_sha256" "$catalog_sha256" <<'PY'
import json
import pathlib
import sys

path, version, revision, dirty, fingerprint, go_version, wasm_manifest_sha256, catalog_sha256 = sys.argv[1:]
result = {
    "schema_version": "cicada.binary-release.v1",
    "transport_variant": "standard",
    "pqtls_available": False,
    "cgo_enabled": False,
    "software_version": version,
    "source": {
        "revision": revision,
        "dirty": dirty == "true",
        "source_fingerprint": fingerprint,
        "fingerprint_descriptor": {"algorithm": "sha256", "domain_hex": b"cicada-binary-release-inputs-v2\0".hex(),
                                   "scope": ["cicada-go", "scripts/build-release.sh", "scripts/hub-build-input-inventory.py", "scripts/write-web-panel-manifest.py", ".github/workflows/release.yml"]},
    },
    "toolchain": go_version.split()[2],
    "hub_webcrypto_manifest_sha256": wasm_manifest_sha256,
    "catalog_sha256": catalog_sha256,
    "targets": [
        "linux/amd64",
        "linux/arm64",
        "darwin/amd64",
        "darwin/arm64",
        "windows/amd64",
    ],
}
pathlib.Path(path).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
(cd "$stage_dir" && sha256sum cicada-* BUILD-METADATA.json LICENSE-NOTICES.tar.gz > SHA256SUMS)
fi

if [[ "$(git -C "$repo_root" rev-parse HEAD)" != "$revision" ||
      "$(compute_dirty)" != "$dirty" ||
      "$(compute_source_fingerprint)" != "$source_fingerprint" ]]; then
  printf 'build-release: build inputs changed during the build; rerun from a stable checkout\n' >&2
  exit 1
fi

if [[ "$out_dir" != /* ]]; then
  out_dir="$PWD/$out_dir"
fi
mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"
cp "$stage_dir"/* "$out_dir/"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    printf 'version=%s\n' "$version"
    printf 'revision=%s\n' "$revision"
    printf 'dirty=%s\n' "$dirty"
    printf 'source_fingerprint=%s\n' "$source_fingerprint"
    printf 'hub_webcrypto_manifest_sha256=%s\n' "$wasm_manifest_sha256"
    printf 'catalog_sha256=%s\n' "$catalog_sha256"
  } >> "$GITHUB_OUTPUT"
fi
printf 'release artifacts written to %s\n' "$out_dir"
printf 'source revision: %s\nsource dirty: %s\nsource fingerprint: %s\n' \
  "$revision" "$dirty" "$source_fingerprint"
