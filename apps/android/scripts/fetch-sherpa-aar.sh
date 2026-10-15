#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client/deps"
archive="$data_dir/sherpa-onnx-1.13.8.aar"
expected="633c24321e06b1fe79feafa03ea16cbc0f8a286641e2da3559bac91bdb13bd96"
mkdir -p "$data_dir" "$repo_dir/android/app/libs"
if [[ ! -f "$archive" ]]; then
  curl -fL --retry 2 \
    https://github.com/k2-fsa/sherpa-onnx/releases/download/v1.13.8/sherpa-onnx-1.13.8.aar \
    -o "$archive"
fi
actual="$(sha256sum "$archive" | cut -d ' ' -f 1)"
if [[ "$actual" != "$expected" ]]; then
  rm -f "$archive"
  echo "sherpa-onnx AAR checksum mismatch" >&2
  exit 1
fi
cp "$archive" "$repo_dir/android/app/libs/sherpa-onnx-1.13.8.aar"
