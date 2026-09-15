#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${CODEX_HOME:?}" /workspace /var/log/cicada/codex

# Seed the packaged defaults only on a fresh state directory. The runtime
# config must remain writable so Codex can persist project trust and TUI
# preferences in CODEX_HOME.
if [[ ! -e "${CODEX_HOME}/config.toml" && -f /etc/codex/config.toml ]]; then
  install -m 600 /etc/codex/config.toml "${CODEX_HOME}/config.toml"
fi

# Keep an existing persistent Codex state aligned with the repository's
# selected model. Earlier Codex versions may have migrated this line to a
# different default; the explicit Cicada runtime contract is gpt-5.5.
if [[ -f "${CODEX_HOME}/config.toml" ]]; then
  config_tmp="${CODEX_HOME}/config.toml.tmp.$$"
  if grep -qE '^model[[:space:]]*=' "${CODEX_HOME}/config.toml"; then
    sed -E 's/^model[[:space:]]*=.*/model = "gpt-5.5"/' \
      "${CODEX_HOME}/config.toml" >"${config_tmp}"
  else
    cat "${CODEX_HOME}/config.toml" >"${config_tmp}"
    printf '\nmodel = "gpt-5.5"\n' >>"${config_tmp}"
  fi
  chmod 0600 "${config_tmp}"
  # A previous container may have created the file as root. Replacing it via
  # the writable state directory still works for the unprivileged runtime user.
  mv -f "${config_tmp}" "${CODEX_HOME}/config.toml"
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
      '{status:"ok", codex_version:$version, model:"gpt-5.5", provider:"basil"}'
    ;;
  *)
    exec "$@"
    ;;
esac
