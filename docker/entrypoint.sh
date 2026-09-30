#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${CODEX_HOME:?}" /workspace /var/log/cicada/codex

# Seed the packaged defaults only on a fresh state directory. The runtime
# config must remain writable so Codex can persist project trust and TUI
# preferences in CODEX_HOME.
if [[ ! -e "${CODEX_HOME}/config.toml" && -f /etc/codex/config.toml ]]; then
  install -m 600 /etc/codex/config.toml "${CODEX_HOME}/config.toml"
fi

configured_codex_value() {
  local key="$1"
  [[ -f "${CODEX_HOME}/config.toml" ]] || return 0
  awk -v key="$key" '
    /^[[:space:]]*\[/ { exit }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line !~ ("^" key "[[:space:]]*=")) next
      sub(/^[^=]*=[[:space:]]*/, "", line)
      if (line ~ /^"[^"]*"/) {
        sub(/^"/, "", line)
        sub(/".*/, "", line)
        print line
      }
      exit
    }
  ' "${CODEX_HOME}/config.toml"
}

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
    model="$(configured_codex_value model)"
    provider="$(configured_codex_value model_provider)"
    jq -cn --arg version "$version" --arg model "$model" --arg provider "$provider" \
      '{status:"ok", codex_version:$version,
        model:(if $model == "" then null else $model end),
        provider:(if $provider == "" then null else $provider end),
        configuration_source:"CODEX_HOME/config.toml"}'
    ;;
  *)
    exec "$@"
    ;;
esac
