#!/usr/bin/env bash
# Start a complete local Cowrie lab, open an SSH session into the honeypot, and
# shut everything down when the SSH session exits.
#
# Usage:
#   ./scripts/run_local_cowrie_lab.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deploy/cowrie/docker-compose.yml"
VAR_DIR="$ROOT_DIR/deploy/cowrie/var"
LOG_FILE="$VAR_DIR/log/cowrie/cowrie.json"
ADAPTER_LOG="$VAR_DIR/cowrie-adapter.log"
FORWARDER_LOG="$VAR_DIR/cowrie-forwarder.log"
KNOWN_HOSTS="$VAR_DIR/known_hosts"
RUNTIME_DIR="$ROOT_DIR/data/runtime"

PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
ADAPTER_HOST="${COWRIE_ADAPTER_HOST:-127.0.0.1}"
ADAPTER_PORT="${COWRIE_ADAPTER_PORT:-8081}"
COWRIE_SSH_HOST="${COWRIE_SSH_HOST:-127.0.0.1}"
COWRIE_SSH_BIND="${COWRIE_SSH_BIND:-127.0.0.1}"
COWRIE_SSH_PORT="${COWRIE_SSH_PORT:-2222}"
ADAPTER_URL="http://$ADAPTER_HOST:$ADAPTER_PORT/v1/cowrie/events"

adapter_pid=""
forwarder_pid=""

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

cleanup() {
  set +e
  echo
  echo "Shutting down local Cowrie lab..."

  if [[ -n "$forwarder_pid" ]]; then
    # Give the tailing forwarder a moment to post final session.closed events
    # written when the SSH client exits.
    sleep 1
    kill "$forwarder_pid" >/dev/null 2>&1
    wait "$forwarder_pid" >/dev/null 2>&1
  fi

  if [[ -n "$adapter_pid" ]]; then
    kill "$adapter_pid" >/dev/null 2>&1
    wait "$adapter_pid" >/dev/null 2>&1
  fi

  "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" down >/dev/null 2>&1
}

wait_for_http() {
  local url="$1"
  local label="$2"
  local attempts="${3:-30}"

  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for $label at $url" >&2
  return 1
}

stop_legacy_cowrie_container() {
  # Earlier manual tests often use `docker run --name cowrie ...`. Stop that
  # known old lab container so this script can consistently own port 2222.
  if docker ps --format "{{.Names}}" | grep -Fxq "cowrie"; then
    echo "Stopping existing legacy Cowrie container named 'cowrie'..."
    docker stop cowrie >/dev/null
  fi
}

rotate_cowrie_log() {
  if [[ -f "$LOG_FILE" ]]; then
    local timestamp
    timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
    mv "$LOG_FILE" "$LOG_FILE.$timestamp.bak"
  fi
}

reset_runtime_state() {
  mkdir -p "$RUNTIME_DIR"
  rm -f \
    "$RUNTIME_DIR/bindings.json" \
    "$RUNTIME_DIR/cowrie_observations.json" \
    "$RUNTIME_DIR/evidence.json" \
    "$RUNTIME_DIR/profiles.json"
}

wait_for_cowrie_ready() {
  local label="$1"
  local attempts="${2:-60}"

  for _ in $(seq 1 "$attempts"); do
    # Poll container logs instead of opening an SSH socket. A socket probe looks
    # like an attacker session to Cowrie and pollutes the demo output.
    if "${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" logs --no-color --tail=80 cowrie \
      2>/dev/null | grep -q "Ready to accept SSH connections"; then
      return 0
    fi
    sleep 1
  done

  echo "Timed out waiting for $label to report SSH readiness" >&2
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

This usually happens after Docker created deploy/cowrie/var/lib/cowrie as
nobody/nogroup. Fix the local lab directory permissions once with:

  sudo mkdir -p "$VAR_DIR/log/cowrie" "$VAR_DIR/lib/cowrie/tty"
  sudo chown -R "$(id -u):$(id -g)" "$VAR_DIR"
  chmod -R u+rwX "$VAR_DIR"

Then rerun:
  ./scripts/run_local_cowrie_lab.sh
EOF
  exit 1
}

choose_compose_cmd

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python interpreter not found or not executable: $PYTHON_BIN" >&2
  echo "Set PYTHON_BIN=/path/to/python if you use a different virtualenv." >&2
  exit 1
fi

mkdir -p "$VAR_DIR"
prepare_cowrie_var_dir
reset_runtime_state
export COWRIE_SSH_BIND COWRIE_SSH_PORT

trap cleanup EXIT INT TERM

# Clear stale containers from this compose project, but do not stop unrelated
# containers that might also be using port 2222.
"${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
stop_legacy_cowrie_container

echo "Starting Cowrie adapter API on $ADAPTER_HOST:$ADAPTER_PORT..."
"$PYTHON_BIN" -m uvicorn services.cowrie.app:app \
  --host "$ADAPTER_HOST" \
  --port "$ADAPTER_PORT" \
  >"$ADAPTER_LOG" 2>&1 &
adapter_pid="$!"
wait_for_http "http://$ADAPTER_HOST:$ADAPTER_PORT/healthz" "Cowrie adapter"

rotate_cowrie_log

echo "Starting Cowrie container on $COWRIE_SSH_HOST:$COWRIE_SSH_PORT..."
"${COMPOSE_CMD[@]}" -f "$COMPOSE_FILE" up -d
wait_for_cowrie_ready "Cowrie"

echo "Starting Cowrie log forwarder..."
"$PYTHON_BIN" "$ROOT_DIR/scripts/forwarders/cowrie_json.py" \
  --from-start \
  --log-file "$LOG_FILE" \
  --adapter-url "$ADAPTER_URL" \
  --poll-seconds 0.2 \
  >"$FORWARDER_LOG" 2>&1 &
forwarder_pid="$!"

echo
echo "Cowrie lab is ready."
echo "Try a fake password. Type 'exit' inside the Cowrie shell to close the lab."
echo "Runtime output:"
echo "  data/runtime/cowrie_observations.json"
echo "  data/runtime/evidence.json"
echo "  data/runtime/profiles.json"
echo

set +e
ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile="$KNOWN_HOSTS" \
  -o LogLevel=ERROR \
  -p "$COWRIE_SSH_PORT" \
  "root@$COWRIE_SSH_HOST"
ssh_status="$?"
set -e

exit "$ssh_status"
