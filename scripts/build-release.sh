#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'usage: %s VERSION [OUTPUT_DIR]\n' "$0" >&2
  printf 'builds checksummed CICADA binaries with embedded Hub WebCrypto assets and source provenance\n' >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
version="$1"
out_dir="${2:-dist}"
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

compute_source_fingerprint() {
  python3 - "$repo_root" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys

root = os.fsencode(sys.argv[1])
paths = subprocess.run(
    [b"git", b"-C", root, b"ls-files", b"--cached", b"--others", b"--exclude-standard", b"-z", b"--",
     b"cicada-go", b"scripts/build-release.sh", b"scripts/write-web-panel-manifest.py", b".github/workflows/release.yml"],
    check=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
).stdout.split(b"\0")
digest = hashlib.sha256(b"cicada-binary-release-inputs-v1\0")
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
  if [[ -n "$(git -C "$repo_root" status --porcelain=v1 --untracked-files=all -- \
      cicada-go scripts/build-release.sh scripts/write-web-panel-manifest.py .github/workflows/release.yml)" ]]; then
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

python3 - "$stage_dir/BUILD-METADATA.json" "$version" "$revision" "$dirty" "$source_fingerprint" "$go_version" "$wasm_manifest_sha256" "$catalog_sha256" <<'PY'
import json
import pathlib
import sys

path, version, revision, dirty, fingerprint, go_version, wasm_manifest_sha256, catalog_sha256 = sys.argv[1:]
result = {
    "schema_version": "cicada.binary-release.v1",
    "software_version": version,
    "source": {
        "revision": revision,
        "dirty": dirty == "true",
        "source_fingerprint": fingerprint,
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
(cd "$stage_dir" && sha256sum cicada-* BUILD-METADATA.json > SHA256SUMS)

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
