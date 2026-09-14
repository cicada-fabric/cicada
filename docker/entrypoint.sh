#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${CODEX_HOME:?}" /workspace /var/log/cicada/codex

case "${1:-shell}" in
  shell)
    shift || true
    exec /bin/bash "$@"
    ;;
  codex)
    shift
    exec codex "$@"
    ;;
  version)
    exec codex --version
    ;;
  health)
    version="$(codex --version 2>/dev/null | head -n 1)"
    jq -cn --arg version "$version" \
      '{status:"ok", codex_version:$version, model:"gpt-5.4", provider:"basil"}'
    ;;
  *)
    exec "$@"
    ;;
esac

