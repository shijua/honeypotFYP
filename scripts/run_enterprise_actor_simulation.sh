#!/usr/bin/env bash
set -euo pipefail

CONTROL_FILE="docker-compose.control.yml"
ENTERPRISE_FILE="docker-compose.enterprise.yml"

if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

PROJECT_NAME="${PROJECT_NAME:-honeynet}"
CLIENT_TARGET_HOST="${CLIENT_TARGET_HOST:-127.0.0.1}"
PUBLIC_PORTAL_PORT="${PUBLIC_PORTAL_PORT:-8080}"
ENTRYPOINT_OBSERVER_PORT="${ENTRYPOINT_OBSERVER_PORT:-8083}"
ATTACKER_IP="${ATTACKER_IP:-198.51.$((RANDOM % 100)).$((RANDOM % 254 + 1))}"
SESSION_ID="${SESSION_ID:-enterprise-sim-$(date +%s)}"
WAIT_RETRIES="${WAIT_RETRIES:-60}"
WAIT_DELAY_SECONDS="${WAIT_DELAY_SECONDS:-2}"
RESET_BEFORE_RUN="${RESET_BEFORE_RUN:-1}"
RESET_RUNTIME_STATE="${RESET_RUNTIME_STATE:-1}"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is not available. Install the Docker Compose plugin or docker-compose." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for this simulation." >&2
  exit 1
fi

wait_for_docker_http() {
  local network="$1"
  local url="$2"
  docker run --rm --network "$network" curlimages/curl:latest -fs --retry "$WAIT_RETRIES" --retry-connrefused --retry-delay "$WAIT_DELAY_SECONDS" --max-time 5 "$url" >/dev/null
}

docker_get() {
  local network="$1"
  local url="$2"
  docker run --rm --network "$network" curlimages/curl:latest -fsS "$url"
}

docker_http_status() {
  local network="$1"
  local url="$2"
  docker run --rm --network "$network" curlimages/curl:latest -s -o /dev/null -w "%{http_code}" "$url"
}

docker_post_json() {
  local network="$1"
  local url="$2"
  docker run --rm -i --network "$network" curlimages/curl:latest -fsS -H "Content-Type: application/json" --data-binary @- "$url"
}

timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

cowrie_event_payload() {
  local eventid="$1"
  local command="${2:-}"
  jq -n \
    --arg eventid "$eventid" \
    --arg ts "$(timestamp_utc)" \
    --arg src_ip "$ATTACKER_IP" \
    --arg session "$SESSION_ID" \
    --arg command "$command" \
    '{
      event: {
        eventid: $eventid,
        timestamp: $ts,
        src_ip: $src_ip,
        session: $session,
        sensor: "enterprise-sim",
        username: "root",
        password: "toor",
        input: (if $command == "" then null else $command end),
        message: "enterprise actor simulation"
      },
      protocol: "ssh"
    }'
}

if [[ "$RESET_BEFORE_RUN" == "1" ]]; then
  reset_args=(--quiet)
  if [[ "$RESET_RUNTIME_STATE" != "1" ]]; then
    reset_args+=(--keep-state)
  fi
  PROJECT_NAME="$PROJECT_NAME" ./scripts/reset_enterprise_runtime.sh "${reset_args[@]}"
fi

echo "Starting enterprise compose slice..."
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" up -d
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" up -d

echo "Waiting for services..."
wait_for_docker_http "${PROJECT_NAME}_net_public" "http://public-portal/"
wait_for_docker_http "${PROJECT_NAME}_net_control" "http://profiler:8002/docs"
wait_for_docker_http "${PROJECT_NAME}_net_control" "http://cowrie-adapter:8011/healthz"
wait_for_docker_http "${PROJECT_NAME}_net_control" "http://controller:8003/docs"
wait_for_docker_http "${PROJECT_NAME}_net_control" "http://orchestrator:8005/docs"
wait_for_docker_http "${PROJECT_NAME}_net_control" "http://gateway:8004/docs"

echo
echo "Normal user surface:"
normal_status="$(docker_http_status "${PROJECT_NAME}_net_public" "http://public-portal/")"
host_status="$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://$CLIENT_TARGET_HOST:$PUBLIC_PORTAL_PORT/" || true)"
echo "  synthetic normal client -> public-portal / -> HTTP $normal_status"
if [[ "$host_status" != "000" && -n "$host_status" ]]; then
  echo "  host port $CLIENT_TARGET_HOST:$PUBLIC_PORTAL_PORT -> HTTP $host_status"
else
  echo "  host port $CLIENT_TARGET_HOST:$PUBLIC_PORTAL_PORT was not reachable from this shell"
fi

echo
echo "Attacker-facing HTTP probe:"
http_probe_status="$(curl -s -o /dev/null -w "%{http_code}" -A "sqlmap/1.8 enterprise-sim" "http://$CLIENT_TARGET_HOST:$ENTRYPOINT_OBSERVER_PORT/.env")"
echo "  host attacker -> entrypoint-observer /.env -> HTTP $http_probe_status"

echo
echo "Attacker SSH telemetry:"
cowrie_event_payload "cowrie.login.failed" | docker_post_json "${PROJECT_NAME}_net_control" "http://cowrie-adapter:8011/v1/cowrie/events" >/dev/null
command_response="$(cowrie_event_payload "cowrie.command.input" "cat /etc/passwd" | docker_post_json "${PROJECT_NAME}_net_control" "http://cowrie-adapter:8011/v1/cowrie/events")"
binding_id="$(echo "$command_response" | jq -r ".binding.binding_id")"
profile="$(echo "$command_response" | jq ".profile")"
unlocked_assets="$(echo "$command_response" | jq ".binding.unlocked_assets")"
echo "  attacker_key: $ATTACKER_IP"
echo "  binding_id: $binding_id"
echo "  recent_tactics: $(echo "$profile" | jq -c ".recent_tactics")"
echo "  recent_techniques: $(echo "$profile" | jq -c ".recent_techniques")"

echo
echo "Controller decision:"
controller_payload="$(jq -n \
  --arg attacker_key "$ATTACKER_IP" \
  --arg binding_id "$binding_id" \
  --argjson profile "$profile" \
  --argjson unlocked_asset_ids "$unlocked_assets" \
  '{
    attacker_key: $attacker_key,
    binding_id: $binding_id,
    profile: $profile,
    unlocked_asset_ids: $unlocked_asset_ids
  }')"
controller_response="$(echo "$controller_payload" | docker_post_json "${PROJECT_NAME}_net_control" "http://controller:8003/v1/controller/tick")"
actions_to_apply="$(echo "$controller_response" | jq ".actions | map(select(.action_type == \"unlock\")) | .[:1]")"
echo "  candidate_asset_ids: $(echo "$controller_response" | jq -c ".candidate_asset_ids")"
echo "  actions_to_apply: $(echo "$actions_to_apply" | jq -c ".")"

if [[ "$(echo "$actions_to_apply" | jq "length")" -eq 0 ]]; then
  echo "  no unlock action returned; simulation stops before orchestrator apply"
  exit 0
fi

echo
echo "Orchestrator apply:"
apply_payload="$(jq -n \
  --arg binding_id "$binding_id" \
  --argjson actions "$actions_to_apply" \
  '{
    binding_id: $binding_id,
    actions: $actions
  }')"
apply_response="$(echo "$apply_payload" | docker_post_json "${PROJECT_NAME}_net_control" "http://orchestrator:8005/v1/orchestration/apply")"
echo "  route_updates: $(echo "$apply_response" | jq -c ".route_updates")"
echo "  runtime_events: $(echo "$apply_response" | jq -c "[.runtime_events[]? | {asset_id, status, settings}]")"

echo
echo "Gateway state:"
gateway_state="$(docker_get "${PROJECT_NAME}_net_control" "http://gateway:8004/v1/gateway/bindings/$binding_id")"
echo "$gateway_state" | jq "{binding_id, attacker_key, exposed_assets, failed_assets, route_updates}"

echo
echo "Simulation complete. Cleanup when done with:"
echo "  ./scripts/reset_enterprise_runtime.sh"
