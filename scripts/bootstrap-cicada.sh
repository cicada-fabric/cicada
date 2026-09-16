#!/usr/bin/env bash
set -euo pipefail

data_root="${CICADA_DATA_ROOT:-/gpu1-share/data/cicada}"
secret_dir="$data_root/secrets"
env_file="$secret_dir/cicada.env"

install -d -m 0755 \
  "$data_root" \
  "$data_root/state/control" \
  "$data_root/state/worker" \
  "$data_root/state/telegram" \
  "$data_root/workspaces" \
  "$data_root/logs/control" \
  "$data_root/logs/worker" \
  "$data_root/logs/telegram" \
  "$data_root/images" \
  "$data_root/vendor"
install -d -m 0700 "$secret_dir"

if [[ ! -s "$env_file" ]]; then
  : "${API_KEY:?Set API_KEY in the environment when creating the secret file}"
  umask 077
  : > "$env_file"
  for name in \
    API_KEY \
    CICADA_API_TOKEN \
    CICADA_WEBHOOK_SECRET \
    CICADA_CONNECTOR_SECRET_TELEGRAM \
    CICADA_TELEGRAM_BOT_TOKEN \
    CICADA_PEER_RELAY_TOKEN; do
    value="${!name:-}"
    [[ -n "$value" ]] || continue
    if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
      printf '%s must not contain a newline\n' "$name" >&2
      exit 1
    fi
    printf '%s=%s\n' "$name" "$value" >> "$env_file"
  done
  printf 'Created %s\n' "$env_file"
else
  chmod 0600 "$env_file"
  printf 'Using existing %s\n' "$env_file"
fi

printf 'Cicada data root: %s\n' "$data_root"
printf 'Secret file mode: '
stat -c '%a' "$env_file"
