#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'usage: %s VERSION [OUTPUT_DIR]\n' "$0" >&2
  printf 'builds cicada binaries for Linux, macOS, and Windows\n' >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
version="$1"
out_dir="${2:-dist}"
[[ "$version" =~ ^[0-9A-Za-z.-]+$ ]] || { printf 'invalid version: %s\n' "$version" >&2; exit 2; }

command -v go >/dev/null 2>&1 || { printf 'build-release: Go is required\n' >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { printf 'build-release: sha256sum is required\n' >&2; exit 1; }
[[ -f cicada-go/go.mod ]] || { printf 'run this script from the repository root\n' >&2; exit 1; }

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"
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
  output="$out_dir/cicada-${os}-${arch}${suffix}"
  printf 'building %s\n' "$output"
  (cd cicada-go && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w -X github.com/cicada-ai/cicada/internal/buildinfo.Version=${version}" \
    -o "$output" ./cmd/cicada)
done

(cd "$out_dir" && sha256sum cicada-* > SHA256SUMS)
printf 'release artifacts written to %s\n' "$out_dir"
