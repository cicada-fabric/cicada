#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
if [[ "$docker_root" != /gpu1-share/data/* ]]; then
  echo "Docker data root is outside /gpu1-share/data: $docker_root" >&2
  exit 1
fi
"$repo_dir/scripts/fetch-sherpa-aar.sh"
mkdir -p "$data_dir/android-home" "$data_dir/gradle-cache"
docker run --rm --user "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v "$repo_dir:/workspace" \
  -v "$data_dir/node_modules:/workspace/node_modules" \
  -v "$data_dir/gradle-cache:/gradle-cache" \
  -v "$data_dir/android-home:/home/gradle/.android" \
  cicada-client-rn:dev gradle --no-daemon --project-dir /workspace/android \
    :app:assembleDebug :app:assembleDebugAndroidTest
