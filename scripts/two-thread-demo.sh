#!/usr/bin/env bash
set -euo pipefail

api_url="${CICADA_API_URL:-http://127.0.0.1:8787}"
timeout_seconds="${CICADA_DEMO_TIMEOUT_SECONDS:-600}"

command -v curl >/dev/null || { printf 'curl is required\n' >&2; exit 1; }
command -v jq >/dev/null || { printf 'jq is required\n' >&2; exit 1; }
curl -fsS "$api_url/healthz" >/dev/null

create_goal() {
	local machine_id="$1" objective="$2"
	local body
	body="$(jq -nc --arg machine_id "$machine_id" --arg objective "$objective" \
		'{objective:$objective,success_criteria:"Return a concise evidence-backed reply.",machine_id:$machine_id}')"
	curl -fsS -X POST "$api_url/v1/goals" -H 'content-type: application/json' -d "$body"
}

wait_goal() {
	local goal_id="$1" label="$2" deadline=$(( $(date +%s) + timeout_seconds ))
	local response status
	while (( $(date +%s) < deadline )); do
		response="$(curl -fsS "$api_url/v1/goals/$goal_id")"
		status="$(jq -r '.status' <<<"$response")"
		printf '%s status=%s\n' "$label" "$status" >&2
		case "$status" in
			completed)
				printf '%s\n' "$response"
				return 0
				;;
			failed|cancelled)
				printf '%s\n' "$response" >&2
				return 1
				;;
		esac
		sleep 2
	done
	printf '%s timed out after %ss\n' "$label" "$timeout_seconds" >&2
	return 1
}

printf 'Creating Thread A on worker-local and Thread B on control-local...\n'
goal_a_json="$(create_goal worker-local 'You are Thread A. Reply with a concise shared result for Thread B. Do not use tools.')"
goal_b_json="$(create_goal control-local 'You are Thread B. Reply with a concise independent result. Do not use tools.')"
goal_a_id="$(jq -r '.id' <<<"$goal_a_json")"
goal_b_id="$(jq -r '.id' <<<"$goal_b_json")"

goal_a_json="$(wait_goal "$goal_a_id" 'Thread A initial turn')"
goal_b_json="$(wait_goal "$goal_b_id" 'Thread B initial turn')"
worker_a_id="$(jq -r '.worker.id' <<<"$goal_a_json")"
worker_b_id="$(jq -r '.worker.id' <<<"$goal_b_json")"
thread_a_id="$(jq -r '.worker.thread_id' <<<"$goal_a_json")"
thread_b_id="$(jq -r '.worker.thread_id' <<<"$goal_b_json")"
summary_a="$(jq -r '.summary' <<<"$goal_a_json")"
summary_b="$(jq -r '.summary' <<<"$goal_b_json")"

printf '\nA -> B (%s -> %s)\n' "$thread_a_id" "$thread_b_id"
message="Thread A (${thread_a_id}) reports:\n${summary_a}\n\nVerify this result and reply with your conclusion."
curl -fsS -X POST "$api_url/v1/threads/messages" \
	-H 'content-type: application/json' \
	-d "$(jq -nc --arg from "$worker_a_id" --arg to "$worker_b_id" --arg message "$message" \
		'{from_worker_id:$from,to_worker_id:$to,message:$message}')" | jq .
goal_b_json="$(wait_goal "$goal_b_id" 'Thread B peer turn')"
summary_b="$(jq -r '.summary' <<<"$goal_b_json")"

printf '\nB -> A (%s -> %s)\n' "$thread_b_id" "$thread_a_id"
message="Thread B (${thread_b_id}) verified:\n${summary_b}\n\nIncorporate this peer review and provide the shared conclusion."
curl -fsS -X POST "$api_url/v1/threads/messages" \
	-H 'content-type: application/json' \
	-d "$(jq -nc --arg from "$worker_b_id" --arg to "$worker_a_id" --arg message "$message" \
		'{from_worker_id:$from,to_worker_id:$to,message:$message}')" | jq .
goal_a_json="$(wait_goal "$goal_a_id" 'Thread A peer turn')"

printf '\nThread A final summary:\n%s\n' "$(jq -r '.summary' <<<"$goal_a_json")"
printf '\nThread B final summary:\n%s\n' "$summary_b"
printf '\nPeer events:\n'
	for goal_id in "$goal_a_id" "$goal_b_id"; do
	curl -fsS "$api_url/v1/goals/$goal_id/events" |
		jq -r '.events[] | select(.type|IN("PeerMessageSent","PeerMessageReceived","PeerMessageDispatched")) | [.type, (.payload.message_id // (.id|tostring))] | @tsv'
done
