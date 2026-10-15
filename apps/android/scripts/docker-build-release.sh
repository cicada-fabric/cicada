#!/usr/bin/env bash
# Build unsigned per-ABI APKs using an explicitly pinned, cached Docker toolchain.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ! "$1" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "Usage: $0 sha256:<immutable-build-image-id> [--android-test]" >&2
  exit 2
fi
if [[ $# -eq 2 && "$2" != --android-test ]]; then
  echo "Only --android-test is accepted as the second argument" >&2
  exit 2
fi

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="${CICADA_ANDROID_DATA_DIR:-/gpu1-share/data/cicada-client}"
build_image_id="$1"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
if [[ "$docker_root" != /gpu1-share/data/* ]]; then
  echo "Docker data root is outside /gpu1-share/data: $docker_root" >&2
  exit 1
fi
for cached in "$data_dir/node_modules" "$data_dir/gradle-cache" "$data_dir/android-home"; do
  if [[ ! -d "$cached" ]]; then
    echo "Missing development cache: $cached" >&2
    exit 1
  fi
done

tasks=(:app:assembleRelease)
properties=(-PclientAbiSplits=true)
if [[ $# -eq 2 ]]; then
  properties+=(-PclientTestBuildType=release)
  tasks+=(:app:assembleReleaseAndroidTest)
fi

docker run --rm --pull=never --network=none --user "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v "$repo_dir:/workspace" \
  -v "$data_dir/node_modules:/workspace/node_modules" \
  -v "$data_dir/gradle-cache:/gradle-cache" \
  -v "$data_dir/android-home:/home/gradle/.android" \
  -w /workspace "$build_image_id" \
  gradle --no-daemon --offline --project-dir /workspace/android \
    "${properties[@]}" "${tasks[@]}"

echo "$repo_dir/android/app/build/outputs/apk/release"
