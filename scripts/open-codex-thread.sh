#!/usr/bin/env bash
set -euo pipefail

name="${1:-}"
if [[ -z "$name" || ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
	printf 'Usage: %s THREAD_NAME\n' "$0" >&2
	printf 'THREAD_NAME may contain only letters, numbers, dot, underscore, and dash.\n' >&2
	exit 2
fi

workspace="/workspace/$name"
docker compose exec -T control mkdir -p "$workspace"
exec docker compose exec -it control codex -C "$workspace"
