#!/usr/bin/env bash
set -euo pipefail

CONTROL_FILE="docker-compose.control.yml"
ENTERPRISE_FILE="docker-compose.enterprise.yml"
STATE_DIR="data/runtime"

if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

PROJECT_NAME="${PROJECT_NAME:-honeynet}"
KEEP_STATE=0
QUIET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-state)
      KEEP_STATE=1
      ;;
    --quiet)
      QUIET=1
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
  shift
done

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is not available. Install the Docker Compose plugin or docker-compose." >&2
  exit 1
fi

log() {
  if [[ "$QUIET" != "1" ]]; then
    echo "$@"
  fi
}

compose_down() {
  local compose_file="$1"
  local label="$2"
  if [[ "$QUIET" == "1" ]]; then
    if ! "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$compose_file" down --remove-orphans >/dev/null 2>&1; then
      echo "Warning: failed to stop $label compose slice" >&2
    fi
    return
  fi
  if ! "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$compose_file" down --remove-orphans; then
    echo "Warning: failed to stop $label compose slice" >&2
  fi
}

write_state() {
  local path="$1"
  local payload="$2"
  local dir
  local tmp
  dir="$(dirname "$path")"
  mkdir -p "$dir"
  tmp="$(mktemp "$dir/.reset.XXXXXX")"
  printf '%s\n' "$payload" >"$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$path"
}

truncate_log() {
  local path="$1"
  local dir
  local tmp
  dir="$(dirname "$path")"
  mkdir -p "$dir"
  tmp="$(mktemp "$dir/.reset-log.XXXXXX")"
  chmod 666 "$tmp" || true
  mv -f "$tmp" "$path"
}

remove_runtime_containers() {
  if ! command -v docker >/dev/null 2>&1; then
    return
  fi
  legacy_containers=(
    "${PROJECT_NAME}_opencanary-entrypoint_1"
    "${PROJECT_NAME}_mail-relay_1"
  )
  legacy_to_remove=()
  for container_name in "${legacy_containers[@]}"; do
    if docker ps -aq --filter "name=^/${container_name}$" >/tmp/honeynet-reset-legacy-container 2>/dev/null; then
      if [[ -s /tmp/honeynet-reset-legacy-container ]]; then
        legacy_to_remove+=("$container_name")
      fi
    fi
  done
  rm -f /tmp/honeynet-reset-legacy-container
  if [[ "${#legacy_to_remove[@]}" -gt 0 ]]; then
    log "Removing legacy compose containers..."
    docker rm -f "${legacy_to_remove[@]}" >/dev/null
  fi

  mapfile -t runtime_containers < <(docker ps -aq --filter label=honeynet.mvp=true)
  if [[ "${#runtime_containers[@]}" -gt 0 ]]; then
    log "Removing dynamic runtime containers..."
    docker rm -f "${runtime_containers[@]}" >/dev/null
  fi
}

remove_runtime_containers

log "Stopping enterprise containers for project $PROJECT_NAME..."
compose_down "$ENTERPRISE_FILE" "enterprise"
compose_down "$CONTROL_FILE" "control"
remove_runtime_containers

if [[ "$KEEP_STATE" == "1" ]]; then
  log "Keeping runtime state under $STATE_DIR"
  exit 0
fi

log "Resetting runtime state under $STATE_DIR..."
write_state "$STATE_DIR/bindings.json" '{"records": []}'
write_state "$STATE_DIR/cowrie_observations.json" '{"observations": []}'
write_state "$STATE_DIR/entrypoint_observations.json" '{"observations": []}'
write_state "$STATE_DIR/opencanary_observations.json" '{"observations": []}'
write_state "$STATE_DIR/evidence.json" '{"records": {}}'
write_state "$STATE_DIR/profiles.json" '{"profiles": {}}'
write_state "$STATE_DIR/gateway_routes.json" '{"routes": []}'
write_state "$STATE_DIR/asset_gateway_routes.json" '{"routes": []}'
write_state "$STATE_DIR/asset_runtime.json" '{"records": []}'
write_state "$STATE_DIR/decision_trace.json" '{"records": []}'
write_state "$STATE_DIR/adaptive_loop_state.json" '{"processed_evidence_ids_by_attacker": {}}'
write_state "$STATE_DIR/adaptive_demo_report.json" '{"schema_version": "v1", "attackers": []}'
truncate_log "deploy/public-portal/logs/access.log"
truncate_log "deploy/opencanary/var/opencanary.log"
truncate_log "deploy/cowrie/var/log/cowrie/cowrie.json"

log "Enterprise runtime reset complete."
