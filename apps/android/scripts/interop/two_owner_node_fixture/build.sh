#!/usr/bin/env bash
set -euo pipefail

FIXED_COMMIT=${FIXTURE_CORE_COMMIT:-967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a}
case "$FIXED_COMMIT" in
  967dbd885fae9a150b3d9a77c8e4e30da1d0dd8a|be0269e80c41e94881d131bd4f4b233e80b6ffe6) ;;
  *) echo "unsupported fixed fixture source" >&2; exit 2 ;;
esac
GO_BUILDER_IMAGE=sha256:3680233e3204827fbdc66088528ae6d4b3d034f51d03a99d454f6de034888244
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CLIENT_ROOT=$(cd -- "$SCRIPT_DIR/../../.." && pwd)
CORE_REPO=${CORE_REPO:-"$CLIENT_ROOT/../CICADA"}
FIXTURE_BUILD_ROOT=${FIXTURE_BUILD_ROOT:-/gpu1-share/data/cicada-client/two-owner-node-fixture-build}

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build this helper" >&2
  exit 2
fi
if ! git -C "$CORE_REPO" cat-file -e "${FIXED_COMMIT}^{commit}" 2>/dev/null; then
  echo "fixed CICADA commit is unavailable in CORE_REPO" >&2
  exit 2
fi
CORE_REPO=$(cd -- "$CORE_REPO" && pwd -P)
CLIENT_ROOT=$(cd -- "$CLIENT_ROOT" && pwd -P)
FIXTURE_BUILD_ROOT=$(realpath -m -- "$FIXTURE_BUILD_ROOT")
if [[ "$FIXTURE_BUILD_ROOT" == "/" || "${FIXTURE_BUILD_ROOT##*/}" != "two-owner-node-fixture-build" ]]; then
  echo "FIXTURE_BUILD_ROOT must be a dedicated two-owner-node-fixture-build directory" >&2
  exit 2
fi
case "$FIXTURE_BUILD_ROOT/" in
  "$CLIENT_ROOT/"*|"$CORE_REPO/"*)
    echo "FIXTURE_BUILD_ROOT must be outside both Git repositories" >&2
    exit 2
    ;;
esac

mkdir -p "$FIXTURE_BUILD_ROOT/source" "$FIXTURE_BUILD_ROOT/bin" "$FIXTURE_BUILD_ROOT/cache"
for directory in "$FIXTURE_BUILD_ROOT/source" "$FIXTURE_BUILD_ROOT/bin" "$FIXTURE_BUILD_ROOT/cache"; do
  if [[ -L "$directory" || ! -d "$directory" ]]; then
    echo "build cache entries must be real directories" >&2
    exit 2
  fi
  chmod 700 "$directory"
done
SOURCE_DIR=$(mktemp -d "$FIXTURE_BUILD_ROOT/source/archive.XXXXXX")
trap 'rm -rf -- "$SOURCE_DIR"' EXIT
mkdir -m 700 "$SOURCE_DIR/core"

# `git archive` uses only the requested clean source commit even if CORE_REPO
# has unrelated uncommitted work.
git -C "$CORE_REPO" archive --format=tar "$FIXED_COMMIT" | tar -xf - -C "$SOURCE_DIR/core"
mkdir -p "$SOURCE_DIR/core/cicada-go/cmd/two-owner-node-fixture"
install -m 600 "$SCRIPT_DIR/main.go" "$SOURCE_DIR/core/cicada-go/cmd/two-owner-node-fixture/main.go"

proxy_args=()
if [[ -n "${FIXTURE_HTTP_PROXY:-}" ]]; then
  proxy_args=(--network host
    -e "HTTPS_PROXY=$FIXTURE_HTTP_PROXY" -e "HTTP_PROXY=$FIXTURE_HTTP_PROXY"
    -e NO_PROXY=localhost,127.0.0.1)
fi
docker run --rm \
  "${proxy_args[@]}" \
  --user "$(id -u):$(id -g)" \
  -v "$SOURCE_DIR/core:/src:ro" \
  -v "$FIXTURE_BUILD_ROOT/bin:/out" \
  -v "$FIXTURE_BUILD_ROOT/cache:/cache" \
  -w /src/cicada-go \
  -e GOPATH=/cache/gopath \
  -e GOMODCACHE=/cache/gomod \
  -e GOCACHE=/cache/gobuild \
  "$GO_BUILDER_IMAGE" \
  go build -mod=readonly -trimpath \
    -ldflags "-X main.sourceCommit=$FIXED_COMMIT" \
    -o /out/two-owner-node-fixture \
    ./cmd/two-owner-node-fixture
chmod 700 "$FIXTURE_BUILD_ROOT/bin/two-owner-node-fixture"
docker image inspect --format 'Go builder image ID: {{.Id}}' "$GO_BUILDER_IMAGE"
sha256sum "$FIXTURE_BUILD_ROOT/bin/two-owner-node-fixture"
