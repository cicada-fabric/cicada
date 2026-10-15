#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
if [[ "$docker_root" != /gpu1-share/data/* ]]; then
  echo "Docker data root is outside /gpu1-share/data: $docker_root" >&2
  exit 1
fi
apk="$data_dir/build-output/cicada-client-debug.apk"
if [[ ! -f "$apk" ]]; then
  echo "Build the APK with ./scripts/docker-build.sh first." >&2
  exit 1
fi
docker build -f "$repo_dir/Dockerfile.emulator" -t cicada-client-emulator:dev "$repo_dir"
network_args=()
security_args=()
if [[ "${CICADA_EMULATOR_SECURITY_CHECK:-}" == 1 || "${CICADA_EMULATOR_VECTOR_CHECK:-}" == 1 ]]; then
  test_apk="$repo_dir/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
  if [[ ! -f "$test_apk" ]]; then
    echo 'Build the Android test APK before running the security check.' >&2
    exit 1
  fi
  security_args=(-e CICADA_EMULATOR_SECURITY_CHECK="${CICADA_EMULATOR_SECURITY_CHECK:-}" \
    -e CICADA_EMULATOR_VECTOR_CHECK="${CICADA_EMULATOR_VECTOR_CHECK:-}" \
    -v "$test_apk:/tmp/cicada-test.apk:ro")
fi
if [[ -n "${CICADA_EMULATOR_PROXY:-}" || "${CICADA_EMULATOR_SECURITY_CHECK:-}" == 1 ]]; then
  network_args=(--network host)
fi
docker run --rm --user root --device /dev/kvm "${network_args[@]}" \
  "${security_args[@]}" \
  -e CICADA_EMULATOR_PROXY="${CICADA_EMULATOR_PROXY:-}" \
  -e CICADA_EMULATOR_GUEST_PROXY="${CICADA_EMULATOR_GUEST_PROXY:-10.0.2.2:7890}" \
  -e CICADA_EMULATOR_HUB_BASE_URL="${CICADA_EMULATOR_HUB_BASE_URL:-http://10.0.2.2:8787}" \
  -v "$repo_dir:/workspace:ro" -v "$apk:/tmp/cicada.apk:ro" \
  -v "$data_dir/build-output:/out" \
  cicada-client-emulator:dev bash /workspace/scripts/emulator-smoke.sh
