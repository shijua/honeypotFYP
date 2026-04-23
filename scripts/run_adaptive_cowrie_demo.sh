#!/usr/bin/env bash
# Start a local adaptive Cowrie demo.
#
# The flow is:
#   Cowrie SSH -> forward Cowrie JSON -> Cowrie adapter/profile files
#   -> controller tick -> orchestrator apply -> new Docker asset ports
#
# Usage:
#   ./scripts/run_adaptive_cowrie_demo.sh
#   ./scripts/run_adaptive_cowrie_demo.sh cleanup

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deploy/cowrie/docker-compose.yml"
VAR_DIR="$ROOT_DIR/deploy/cowrie/var"
LOG_FILE="$VAR_DIR/log/cowrie/cowrie.json"
KNOWN_HOSTS="$VAR_DIR/known_hosts"
RUNTIME_DIR="$ROOT_DIR/data/runtime"
PID_FILE="$RUNTIME_DIR/adaptive_cowrie_demo.pids"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
COWRIE_ADAPTER_HOST="${COWRIE_ADAPTER_HOST:-127.0.0.1}"
COWRIE_ADAPTER_PORT="${COWRIE_ADAPTER_PORT:-8081}"
CONTROLLER_HOST="${CONTROLLER_HOST:-127.0.0.1}"
CONTROLLER_PORT="${CONTROLLER_PORT:-8003}"
ORCHESTRATOR_HOST="${ORCHESTRATOR_HOST:-127.0.0.1}"
ORCHESTRATOR_PORT="${ORCHESTRATOR_PORT:-8006}"
COWRIE_SSH_HOST="${COWRIE_SSH_HOST:-127.0.0.1}"
COWRIE_SSH_BIND="${COWRIE_SSH_BIND:-127.0.0.1}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"

ADAPTER_URL="http://$COWRIE_ADAPTER_HOST:$COWRIE_ADAPTER_PORT/v1/cowrie/events"
CONTROLLER_URL="http://$CONTROLLER_HOST:$CONTROLLER_PORT"
ORCHESTRATOR_URL="http://$ORCHESTRATOR_HOST:$ORCHESTRATOR_PORT"

choose_compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD=(docker-compose)
    return
  fi

  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
    return
  fi

  echo "Could not find docker-compose or docker compose." >&2
  exit 1
}

choose_python() {
  if [[ -x "$PYTHON_BIN" ]]; then
    return
  fi
  if command -v python3.10 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.10)"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
    return
  fi
  echo "Could not find a Python interpreter. Set PYTHON_BIN=/path/to/python." >&2
  exit 1
}

record_pid() {
  echo "$1" >> "$PID_FILE"
}

kill_recorded_pids() {
  if [[ ! -f "$PID_FILE" ]]; then
    return
  fi
  while IFS= read -r pid; do
    if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done < "$PID_FILE"
  rm -f "$PID_FILE"
}

stop_honeynet_containers() {
  if ! command -v docker >/dev/null 2>&1; then
    return
  fi

  local ids=()
  mapfile -t ids < <(docker ps -aq --filter "label=honeynet.mvp=true" 2>/dev/null || true)
  if ((${#ids[@]} > 0)); then
    docker rm -f "${ids[@]}" >/dev/null 2>&1 || true
  fi

  # Older runtime records did not have labels, so keep a name-prefix fallback.
  mapfile -t ids < <(docker ps -aq --filter "name=honeynet-" 2>/dev/null || true)
  if ((${#ids[@]} > 0)); then
    docker rm -f "${ids[@]}" >/dev/null 2>&1 || true
  fi
}

reset_runtime_state() {
  mkdir -p "$RUNTIME_DIR"
  rm -f \
    "$RUNTIME_DIR/bindings.json" \
    "$RUNTIME_DIR/cowrie_observations.json" \
    "$RUNTIME_DIR/evidence.json" \
    "$RUNTIME_DIR/profiles.json" \
    "$RUNTIME_DIR/gateway_routes.json" \
    "$RUNTIME_DIR/asset_runtime.json"
}

cleanup() {
  set +e
  echo
  echo "Cleaning up adaptive Cowrie demo..."
  kill_recorded_pids
  "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" down >/dev/null 2>&1
  stop_honeynet_containers
}

cleanup_only() {
  choose_compose_cmd
  cleanup
  reset_runtime_state
  echo "Cleanup complete."
}

wait_for_http() {
  local url="$1"
  local label="$2"
  "$PYTHON_BIN" - "$url" "$label" <<'PY'
import time
import sys
from urllib.request import urlopen

url = sys.argv[1]
label = sys.argv[2]
for _ in range(60):
    try:
        with urlopen(url, timeout=1):
            raise SystemExit(0)
    except Exception:
        time.sleep(1)
print(f"Timed out waiting for {label} at {url}", file=sys.stderr)
raise SystemExit(1)
PY
}

wait_for_cowrie_ready() {
  for _ in $(seq 1 60); do
    if "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" logs --no-color --tail=80 cowrie \
      2>/dev/null | grep -q "Ready to accept SSH connections"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for Cowrie to report SSH readiness." >&2
  return 1
}

prepare_cowrie_var_dir() {
  if mkdir -p "$VAR_DIR/log/cowrie" "$VAR_DIR/lib/cowrie/tty" 2>/dev/null; then
    chmod 0777 \
      "$VAR_DIR" \
      "$VAR_DIR/log" \
      "$VAR_DIR/log/cowrie" \
      "$VAR_DIR/lib" \
      "$VAR_DIR/lib/cowrie" \
      "$VAR_DIR/lib/cowrie/tty"
    return
  fi

  cat >&2 <<EOF
Could not prepare Cowrie writable directories under:
  $VAR_DIR

Fix local Docker-created permissions once with:
  sudo mkdir -p "$VAR_DIR/log/cowrie" "$VAR_DIR/lib/cowrie/tty"
  sudo chown -R "$(id -u):$(id -g)" "$VAR_DIR"
  chmod -R u+rwX "$VAR_DIR"
EOF
  exit 1
}

rotate_cowrie_log() {
  if [[ -f "$LOG_FILE" ]]; then
    local timestamp
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$LOG_FILE" "$LOG_FILE.$timestamp.bak"
  fi
}

start_uvicorn() {
  local module="$1"
  local host="$2"
  local port="$3"
  local log_file="$4"

  echo "Starting $module on $host:$port..."
  "$PYTHON_BIN" -m uvicorn "$module" --host "$host" --port "$port" \
    >"$log_file" 2>&1 &
  record_pid "$!"
}

start_adaptive_loop() {
  echo "Starting adaptive controller loop..."
  "$PYTHON_BIN" "$ROOT_DIR/scripts/adaptive_controller_loop.py" \
    --state-dir "$RUNTIME_DIR" \
    --controller-url "$CONTROLLER_URL" \
    --orchestrator-url "$ORCHESTRATOR_URL" \
    --poll-seconds 2 \
    >"$VAR_DIR/adaptive-controller-loop.log" 2>&1 &
  record_pid "$!"
}

start_forwarder() {
  echo "Starting Cowrie log forwarder..."
  "$PYTHON_BIN" "$ROOT_DIR/scripts/forward_cowrie_json.py" \
    --from-start \
    --log-file "$LOG_FILE" \
    --adapter-url "$ADAPTER_URL" \
    --poll-seconds 0.2 \
    >"$VAR_DIR/cowrie-forwarder.log" 2>&1 &
  record_pid "$!"
}

main() {
  if [[ "${1:-}" == "cleanup" ]]; then
    cleanup_only
    return
  fi

  choose_python
  choose_compose_cmd
  mkdir -p "$RUNTIME_DIR" "$VAR_DIR"

  trap cleanup EXIT INT TERM

  cleanup
  set -euo pipefail
  : > "$PID_FILE"
  prepare_cowrie_var_dir
  reset_runtime_state
  rotate_cowrie_log
  export COWRIE_SSH_BIND COWRIE_SSH_PORT

  start_uvicorn "services.cowrie.app:app" "$COWRIE_ADAPTER_HOST" "$COWRIE_ADAPTER_PORT" "$VAR_DIR/cowrie-adapter.log"
  start_uvicorn "services.controller.app:app" "$CONTROLLER_HOST" "$CONTROLLER_PORT" "$VAR_DIR/controller.log"
  start_uvicorn "services.orchestrator.app:app" "$ORCHESTRATOR_HOST" "$ORCHESTRATOR_PORT" "$VAR_DIR/orchestrator.log"

  wait_for_http "http://$COWRIE_ADAPTER_HOST:$COWRIE_ADAPTER_PORT/healthz" "Cowrie adapter"
  wait_for_http "$CONTROLLER_URL/openapi.json" "controller"
  wait_for_http "$ORCHESTRATOR_URL/openapi.json" "orchestrator"

  echo "Starting Cowrie SSH entrypoint on $COWRIE_SSH_HOST:$COWRIE_SSH_PORT..."
  "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
  "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" up -d
  wait_for_cowrie_ready

  start_forwarder
  start_adaptive_loop

  echo
  echo "Adaptive Cowrie demo is ready."
  echo "Inside Cowrie, try commands that create profile evidence:"
  echo "  id"
  echo "  whoami"
  echo "  uname -a"
  echo "  ls -la /tmp"
  echo
  echo "Watch opened ports in another terminal:"
  echo "  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'"
  echo "  tail -f deploy/cowrie/var/adaptive-controller-loop.log"
  echo
  echo "Runtime files:"
  echo "  data/runtime/profiles.json"
  echo "  data/runtime/asset_runtime.json"
  echo
  echo "Type 'exit' inside Cowrie to stop and clean up this demo."
  echo

  set +e
  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile="$KNOWN_HOSTS" \
    -o LogLevel=ERROR \
    -p "$COWRIE_SSH_PORT" \
    "root@$COWRIE_SSH_HOST"
  local ssh_status="$?"
  set -e

  return "$ssh_status"
}

main "$@"
