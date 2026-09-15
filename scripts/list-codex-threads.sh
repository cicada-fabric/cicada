#!/usr/bin/env bash
set -euo pipefail

# Interactive Codex sessions are stored in CODEX_HOME. The first JSONL record
# contains the stable session UUID and cwd; showing only that record keeps the
# command useful even when a rollout contains a large encrypted history.
docker compose exec -T control bash -lc '
  found=0
  while IFS= read -r path; do
    first="$(sed -n "1p" "$path")"
    record="$(printf "%s" "$first" | jq -r "select(.type == \"session_meta\") | [.payload.session_id, .payload.cwd] | @tsv" 2>/dev/null || true)"
    if [ -n "$record" ]; then
      printf "%s\t%s\t%s\n" "$record" "$path"
      found=1
    fi
  done < <(find /state/sessions -type f -name "rollout-*.jsonl" -printf "%T@ %p\n" | sort -nr | cut -d" " -f2- | head -40)
  if [ "$found" -eq 0 ]; then
    printf "No Codex sessions found. Open a terminal with: docker compose exec -it control codex\n" >&2
    exit 1
  fi
' | {
	printf 'THREAD_ID\tCWD\tROLLOUT\n'
	cat
}
