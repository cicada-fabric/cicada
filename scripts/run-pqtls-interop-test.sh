#!/bin/sh
set -eu

if [ "${CICADA_PQTLS_INTEROP_TARGETARCH:-amd64}" = arm64 ]; then
  echo "arm64 TestPQDistribution is not wired to a target runner; refusing direct execution of the ARM64 package from this amd64 test image" >&2
  exit 2
fi

exec go test -tags cicada_pqtls -count=1 -json -timeout=3m -run '^TestPQDistribution' ./cmd/cicada
