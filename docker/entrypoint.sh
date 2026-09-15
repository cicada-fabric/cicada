#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${CODEX_HOME:?}" /workspace /var/log/cicada/codex

# Seed the packaged defaults only on a fresh state directory. The runtime
# config must remain writable so Codex can persist project trust and TUI
# preferences in CODEX_HOME.
if [[ ! -e "${CODEX_HOME}/config.toml" && -f /etc/codex/config.toml ]]; then
  install -m 600 /etc/codex/config.toml "${CODEX_HOME}/config.toml"
fi

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
