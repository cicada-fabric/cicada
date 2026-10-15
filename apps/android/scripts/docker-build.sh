#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
if [[ "$docker_root" != /gpu1-share/data/* ]]; then
  echo "Docker data root is outside /gpu1-share/data: $docker_root" >&2
  exit 1
fi
mkdir -p "$data_dir/node_modules" "$data_dir/npm-cache" \
  "$data_dir/gradle-cache" "$data_dir/build-output" "$data_dir/android-home"
"$repo_dir/scripts/fetch-sherpa-aar.sh"
"$repo_dir/scripts/fetch-temurin25.sh"
docker build -f "$repo_dir/Dockerfile.android" -t cicada-client-android:dev "$repo_dir"
docker build --build-context "temurin25=$data_dir/toolchains/temurin25" \
  -f "$repo_dir/Dockerfile.react-native" -t cicada-client-rn:dev "$repo_dir"
docker run --rm --user "$(id -u):$(id -g)" \
  -e npm_config_cache=/npm-cache \
  -v "$repo_dir:/workspace" \
  -v "$data_dir/node_modules:/workspace/node_modules" \
  -v "$data_dir/npm-cache:/npm-cache" \
  cicada-client-rn:dev npm ci --no-audit --no-fund
docker run --rm --user "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/gradle-cache \
  -v "$repo_dir:/workspace" \
  -v "$data_dir/node_modules:/workspace/node_modules" \
  -v "$data_dir/gradle-cache:/gradle-cache" \
  -v "$data_dir/android-home:/home/gradle/.android" \
  cicada-client-rn:dev gradle --no-daemon --project-dir /workspace/android :app:assembleDebug
cp "$repo_dir/android/app/build/outputs/apk/debug/app-debug.apk" \
  "$data_dir/build-output/cicada-client-debug.apk"
echo "$data_dir/build-output/cicada-client-debug.apk"
