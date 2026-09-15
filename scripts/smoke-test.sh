#!/usr/bin/env bash
set -euo pipefail

data_root="${CICADA_DATA_ROOT:-/gpu1-share/data/cicada}"
env_file="$data_root/secrets/cicada.env"

docker_root="$(docker info --format '{{.DockerRootDir}}')"
case "$docker_root" in
  /gpu1-share/*) ;;
  *)
    printf 'Docker root must be under /gpu1-share; found %s\n' "$docker_root" >&2
    exit 1
    ;;
esac

[[ -s "$env_file" ]] || {
  printf 'Missing runtime secret file: %s\n' "$env_file" >&2
  exit 1
}
[[ "$(stat -c '%a' "$env_file")" == "600" ]] || {
  printf 'Runtime secret file must have mode 600: %s\n' "$env_file" >&2
  exit 1
}

docker compose config --quiet
docker compose up -d control
docker compose --profile worker up -d worker

for container in cicada-control cicada-worker; do
  for _ in $(seq 1 30); do
    [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == "healthy" ]] && break
    sleep 1
  done
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" == "healthy" ]] || {
    printf '%s did not become healthy\n' "$container" >&2
    exit 1
  }
done

health_json="$(curl -fsS http://127.0.0.1:${CICADA_API_PORT:-8787}/healthz)"
jq -e '.status == "ok" and .service == "cicada-control"' >/dev/null <<<"$health_json"
machines_json="$(curl -fsS http://127.0.0.1:${CICADA_API_PORT:-8787}/v1/machines)"
jq -e '.machines | length >= 2' >/dev/null <<<"$machines_json"

codex_version="$(docker compose exec -T control codex --version)"
doctor_json="$(docker compose exec -T control codex doctor -c 'model="gpt-5.4"' --json)"
docker compose exec -T control sh -lc \
  'test -f /etc/codex/config.toml && test -f "$CODEX_HOME/config.toml" && touch "$CODEX_HOME/.cicada-write-test" && rm "$CODEX_HOME/.cicada-write-test"'

jq -e '
  .checks["auth.credentials"].status == "ok" and
  .checks["auth.credentials"].details["provider auth env var"] == "API_KEY (present)" and
  .checks["config.load"].status == "ok" and
  .checks["config.load"].details.model == "gpt-5.4" and
  .checks["config.load"].details["model provider"] == "basil" and
  .checks.installation.details["managed by npm"] == "false" and
  .checks["network.provider_reachability"].status == "ok"
' >/dev/null <<<"$doctor_json"

printf 'Docker root: %s\n' "$docker_root"
printf 'Codex: %s\n' "$codex_version"
printf 'Containers: control=healthy worker=healthy\n'
printf 'Configuration: model=gpt-5.4 provider=basil auth=present endpoint=reachable\n'

if [[ "${CICADA_SMOKE_INFERENCE:-0}" == "1" ]]; then
  api_url="http://127.0.0.1:${CICADA_API_PORT:-8787}"
  goal_json="$(curl -fsS -X POST "$api_url/v1/goals" \
    -H 'content-type: application/json' \
    -d '{"objective":"Reply with exactly CICADA_READY and do not use tools","success_criteria":"The final answer is exactly CICADA_READY"}')"
  goal_id="$(jq -r '.id' <<<"$goal_json")"
  [[ -n "$goal_id" && "$goal_id" != null ]] || {
    printf 'Control API did not return a Goal id\n' >&2
    exit 1
  }
  final_json=''
  for _ in $(seq 1 300); do
    final_json="$(curl -fsS "$api_url/v1/goals/$goal_id")"
    status="$(jq -r '.status' <<<"$final_json")"
    if [[ "$status" == completed || "$status" == failed || "$status" == cancelled ]]; then
      break
    fi
    sleep 1
  done
  jq -e '.status == "completed" and .summary == "CICADA_READY" and .worker.status == "completed"' >/dev/null <<<"$final_json" || {
    printf 'Unexpected Control inference result: %s\n' "$final_json" >&2
    exit 1
  }
  events_json="$(curl -fsS "$api_url/v1/goals/$goal_id/events")"
  jq -e '[.events[].type] | index("GoalCompleted") != null and index("WorkerCompleted") != null' >/dev/null <<<"$events_json"
  printf 'Inference via Control app-server: CICADA_READY\n'
fi
