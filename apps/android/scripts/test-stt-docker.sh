#!/usr/bin/env bash
set -euo pipefail
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client"
docker_root="$(docker info --format '{{.DockerRootDir}}')"
if [[ "$docker_root" != /gpu1-share/data/* ]]; then
  echo "Docker data root is outside /gpu1-share/data: $docker_root" >&2
  exit 1
fi
model_zip="$data_dir/models/vosk-model-small-cn-0.22.zip"
model_dir="$data_dir/models/vosk-model-small-cn-0.22"
sample="$data_dir/test-data/zh-groundtruth.wav"
expected_zip="3af8b0e7e0f835ae9d414ce5df580237a3cfb08d586c9fbbb0f7ff29ad5b14ba"
expected_sample="4affd509d1ebb95052b50079f4aea3734e05eefc57a018a26618043744e572c9"
if [[ ! -f "$model_zip" || ! -f "$sample" ]]; then
  echo "Download the pinned model and sample described in docs/stt-validation.md first." >&2
  exit 1
fi
printf '%s  %s\n' "$expected_zip" "$model_zip" | sha256sum --check --status
printf '%s  %s\n' "$expected_sample" "$sample" | sha256sum --check --status
if [[ ! -d "$model_dir" ]]; then
  unzip -q "$model_zip" -d "$data_dir/models"
fi
docker build -f "$repo_dir/Dockerfile.stt" -t cicada-client-stt:dev "$repo_dir"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$repo_dir:/workspace:ro" -v "$data_dir:/data:ro" \
  cicada-client-stt:dev python scripts/test_stt.py \
    --model /data/models/vosk-model-small-cn-0.22 \
    --wav /data/test-data/zh-groundtruth.wav \
    --expected '来，哥哥再给你唱首歌。好儿，哎呦，把伴奏给我放起来，放就放嘛，还要躲人家钩子。'
