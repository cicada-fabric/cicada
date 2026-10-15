#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
builder_image='golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61'
node_bin="${NODE_BIN:-$(command -v node || true)}"
generated="${repo_root}/cicada-go/internal/server/ui/generated"
common_dir="$(git -C "$repo_root" rev-parse --path-format=absolute --git-common-dir)"
local_root="$(dirname "$(dirname "$common_dir")")/.local"
work_dir="${CICADA_WEB_PANEL_WORK_DIR:-$local_root/state/web-panel-build}"
interop_wasm="${work_dir}/web-panel-interop-test.wasm"
raw_wasm="${work_dir}/web-panel-production.wasm"
version_file="${work_dir}/web-panel-go-version"
gzip_bin="${GZIP_BIN:-$(command -v gzip || true)}"

for command_name in docker python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'build-web-panel: required command unavailable: %s\n' "$command_name" >&2
    exit 1
  }
done
[[ -n "$node_bin" && -x "$node_bin" ]] || { printf 'build-web-panel: Node 24 LTS or Node 26 is required; set NODE_BIN to its executable path\n' >&2; exit 1; }
[[ "$("$node_bin" -p 'process.versions.node.split(".")[0]')" =~ ^(24|26)$ ]] || { printf 'build-web-panel: Node 24 LTS or Node 26 is required for the WASM gate\n' >&2; exit 1; }
[[ -n "$gzip_bin" && -x "$gzip_bin" ]] || { printf 'build-web-panel: gzip is required\n' >&2; exit 1; }
umask 077
mkdir -p "$generated" "$work_dir"
exec 9>"$work_dir/build.lock"
flock -n 9 || { printf 'build-web-panel: work directory is in use\n' >&2; exit 2; }

docker_args=(run --rm --user "$(id -u):$(id -g)" -v "${repo_root}:/repo" -v "${work_dir}:/work")
if [[ "${CICADA_WEB_PANEL_OFFLINE:-0}" == 1 ]]; then
  gomod_cache="${CICADA_WEB_PANEL_GOMODCACHE:-${local_root}/cache/gomod}"
  gocache="${CICADA_WEB_PANEL_GOCACHE:-${local_root}/cache/web-panel-build}"
  [[ -d "$gomod_cache" && -d "$gocache" ]] || {
    printf 'build-web-panel: offline mode requires CICADA_WEB_PANEL_GOMODCACHE and CICADA_WEB_PANEL_GOCACHE directories\n' >&2
    exit 1
  }
  docker_args+=(--network=none -v "${gomod_cache}:/gomod:ro" -v "${gocache}:/gocache")
  docker_args+=(-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e GOPROXY=off)
else
  gomod_cache="${CICADA_WEB_PANEL_GOMODCACHE:-${work_dir}/web-panel-gomodcache}"
  gocache="${CICADA_WEB_PANEL_GOCACHE:-${work_dir}/web-panel-gocache}"
  mkdir -p "$gomod_cache" "$gocache"
  docker_args+=(-v "${gomod_cache}:/gomod" -v "${gocache}:/gocache")
  docker_args+=(-e GOMODCACHE=/gomod -e GOCACHE=/gocache -e "GOPROXY=${GOPROXY:-https://proxy.golang.org,direct}")
fi
docker_args+=(-w /repo/cicada-go -e GOTOOLCHAIN=local)
docker "${docker_args[@]}" "$builder_image" sh -eu -c '
  assets=/repo/cicada-go/internal/server/ui/generated
  mkdir -p "$assets"
  test "$(go version | cut -d" " -f3)" = go1.27.2
  GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -o /work/web-panel-production.wasm ./cmd/cicada-webcrypto
  GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -tags=cicada_interop_test -o /work/web-panel-interop-test.wasm ./cmd/cicada-webcrypto
  goroot="$(go env GOROOT)"
  runtime="$goroot/lib/wasm/wasm_exec.js"
  if [ ! -f "$runtime" ]; then runtime="$goroot/misc/wasm/wasm_exec.js"; fi
  test -f "$runtime"
  cp "$runtime" "$assets/wasm_exec.js"
  go version > /work/web-panel-go-version
'
"$gzip_bin" -n -9 -c "$raw_wasm" > "$generated/cicada-webcrypto.wasm.gz"
python3 "$repo_root/scripts/write-web-panel-manifest.py" "$generated" "$(cat "$version_file")" "$raw_wasm"
rm -f "$raw_wasm" "$version_file"

for source in "$repo_root"/cicada-go/internal/server/ui/panel*.js; do
  "$node_bin" --input-type=module --check < "$source"
done
"$node_bin" "$repo_root/scripts/test-web-panel.mjs" \
  --wasm "$interop_wasm" --wasm-exec "$generated/wasm_exec.js" \
  --ui "$repo_root/cicada-go/internal/server/ui"

printf 'Hub WebCrypto assets built with go1.27.2; Node %s interoperability and UI model checks passed.\n' "$("$node_bin" --version)"
