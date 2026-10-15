#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
data_dir="/gpu1-share/data/cicada-client"
sha256sum --check <<EOF
c71f0ce00bec95b07744e116345e33d8cbbe08cef896382cf907bf4b51a2cd51  $data_dir/models/sensevoice-2024-07-17/model.int8.onnx
f449eb28dc567533d7fa59be34e2abca878a47fb731a31429a1dc  $data_dir/models/sensevoice-2024-07-17/tokens.txt
3ef6c19369b912f7caf3cef8e545c5ccd1a33d9d7ec792a46668dc41c4b229ec  $data_dir/models/paraformer-zh-small/model.int8.onnx
4b2d964e18b9cf139b473003b6698fb2ed9a2a5ec55b93daa677b28f578897aa  $data_dir/models/paraformer-zh-small/tokens.txt
4affd509d1ebb95052b50079f4aea3734e05eefc57a018a26618043744e572c9  $data_dir/test-data/zh-groundtruth.wav
1a6bf94091d9c35e11aea5d494d05e3287b8f5c767f6de3bfd796d91b637500c  $data_dir/test-data/zh-0.wav
EOF
docker build -f "$repo_dir/Dockerfile.sherpa-stt" -t cicada-client-sherpa-stt:dev "$repo_dir"
for engine in sensevoice paraformer; do
  case "$engine" in
    sensevoice) model="sensevoice-2024-07-17" ;;
    paraformer) model="paraformer-zh-small" ;;
  esac
  for wav in zh-groundtruth.wav zh-0.wav; do
    docker run --rm --user "$(id -u):$(id -g)" \
      -v "$repo_dir:/workspace:ro" -v "$data_dir:/data:ro" \
      cicada-client-sherpa-stt:dev python scripts/test_sherpa_stt.py \
        --engine "$engine" --model "/data/models/$model/model.int8.onnx" \
        --tokens "/data/models/$model/tokens.txt" --wav "/data/test-data/$wav"
  done
done
