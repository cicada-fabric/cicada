#!/usr/bin/env bash
set -euo pipefail

data_root="${CICADA_DATA_ROOT:-/gpu1-share/data/cicada}"
secret_dir="$data_root/secrets"
env_file="$secret_dir/cicada.env"

install -d -m 0755 \
  "$data_root" \
  "$data_root/state/control" \
  "$data_root/state/worker" \
  "$data_root/workspaces" \
  "$data_root/logs/control" \
  "$data_root/logs/worker" \
  "$data_root/images" \
  "$data_root/vendor"
install -d -m 0700 "$secret_dir"

if [[ ! -s "$env_file" ]]; then
  : "${API_KEY:?Set API_KEY in the environment when creating the secret file}"
	umask 077
	printf 'API_KEY=%s\n' "$API_KEY" > "$env_file"
	if [[ -n "${CICADA_API_TOKEN:-}" ]]; then
	  printf 'CICADA_API_TOKEN=%s\n' "$CICADA_API_TOKEN" >> "$env_file"
	fi
	if [[ -n "${CICADA_WEBHOOK_SECRET:-}" ]]; then
	  printf 'CICADA_WEBHOOK_SECRET=%s\n' "$CICADA_WEBHOOK_SECRET" >> "$env_file"
	fi
  printf 'Created %s\n' "$env_file"
else
  chmod 0600 "$env_file"
  printf 'Using existing %s\n' "$env_file"
fi

printf 'Cicada data root: %s\n' "$data_root"
printf 'Secret file mode: '
stat -c '%a' "$env_file"
