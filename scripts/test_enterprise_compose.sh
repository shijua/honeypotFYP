#!/usr/bin/env bash
set -euo pipefail

CONTROL_FILE="docker-compose.control.yml"
ENTERPRISE_FILE="docker-compose.enterprise.yml"

if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

PROJECT_NAME="honeynet"
if [[ -z "${HOST_PROJECT_ROOT:-}" || "${HOST_PROJECT_ROOT:-}" == "." ]]; then
  HOST_PROJECT_ROOT="$PWD"
elif [[ "$HOST_PROJECT_ROOT" != /* ]]; then
  # Compose validation runs from the repo root, but runtime bind mounts still
  # need an absolute path once Docker starts containers.
  HOST_PROJECT_ROOT="$(cd "$HOST_PROJECT_ROOT" && pwd)"
fi

merge_asset_gateway_ports() {
  # Mirror the production start script so the smoke test exercises every
  # gateway listener that adaptive assets may use.
  local merged="$1"
  shift
  local port
  for port in "$@"; do
    [[ -z "$port" ]] && continue
    case ",$merged," in
      *",$port,"*) ;;
      *)
        if [[ -z "$merged" ]]; then
          merged="$port"
        else
          merged="$merged,$port"
        fi
        ;;
    esac
  done
  printf '%s' "$merged"
}

ASSET_GATEWAY_PORTS="$(
  # Keep this list aligned with adaptive internal asset ports in the catalog.
  merge_asset_gateway_ports "${ASSET_GATEWAY_PORTS:-}" \
    "${INTERNAL_PORTAL_PORT:-18080}" \
    "${GIT_INTERNAL_PORT:-19418}" \
    "${OPS_DB_PORT:-13306}" \
    "${REDIS_CACHE_PORT:-16379}" \
    "${WEB_ADMIN_CONSOLE_PORT:-18081}" \
    "${FTP_ARCHIVE_PORT:-12121}" \
    "${SSH_CANARY_PORT:-12222}" \
    "${LEGACY_TELNET_PORT:-12323}" \
    "${MAIL_RELAY_PORT:-2525}" \
    "${FINANCE_SHARE_PORT:-18082}" \
    "${VPN_APPLIANCE_PORT:-18443}" \
    "${MALWARE_SINK_PORT:-18085}" \
    "${DIONAEA_SMB_PORT:-1445}" \
    "${DIONAEA_MSSQL_PORT:-11433}" \
    "${DIONAEA_FTP_PORT:-12122}" \
    "${HONEYTRAP_GENERIC_PORT:-19999}"
)"
export PROJECT_NAME HOST_PROJECT_ROOT ASSET_GATEWAY_PORTS
WAIT_RETRIES="${WAIT_RETRIES:-60}"
WAIT_DELAY_SECONDS="${WAIT_DELAY_SECONDS:-2}"
RESET_BEFORE_RUN="${RESET_BEFORE_RUN:-1}"
HOST_CHECK_ADDRESS="${HOST_BIND_ADDRESS:-127.0.0.1}"
ENTERPRISE_SERVICES=(
  public-portal
  public-portal-forwarder
  asset-gateway
  internal-http-forwarder
  internal-protocol-forwarder
  high-interaction-adapter
  high-interaction-forwarder
  cowrie
  opencanary-adapter
  opencanary-forwarder
  entrypoint-observer
  cowrie-adapter
  cowrie-forwarder
  internal-portal
)

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is not available. Install the Docker Compose plugin or docker-compose." >&2
  exit 1
fi

cleanup() {
  echo "Cleaning up compose test containers..."
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" down --remove-orphans >/dev/null 2>&1 || true
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" down --remove-orphans >/dev/null 2>&1 || true
}

print_debug() {
  echo "Compose service status:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" ps || true
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" ps || true
  echo "Recent profiler logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" logs --tail=80 profiler || true
  echo "Recent OpenCanary adapter logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 opencanary-adapter || true
  echo "Recent OpenCanary forwarder logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 opencanary-forwarder || true
  echo "Recent public portal forwarder logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 public-portal-forwarder || true
  echo "Recent internal HTTP forwarder logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 internal-http-forwarder || true
  echo "Recent internal protocol forwarder logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 internal-protocol-forwarder || true
  echo "Recent public portal logs:"
  "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" logs --tail=40 public-portal || true
}

on_exit() {
  status=$?
  if [[ "$status" -ne 0 ]]; then
    print_debug
  fi
  cleanup
  exit "$status"
}

wait_for_host_http() {
  local url="$1"
  curl -fs --retry "$WAIT_RETRIES" --retry-connrefused --retry-delay "$WAIT_DELAY_SECONDS" --max-time 5 "$url" >/dev/null
}

wait_for_docker_http() {
  local network="$1"
  local url="$2"
  docker run --rm --network "$network" curlimages/curl:latest \
    -fs --retry "$WAIT_RETRIES" --retry-connrefused --retry-delay "$WAIT_DELAY_SECONDS" --max-time 5 "$url" >/dev/null
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local attempt
  for ((attempt = 1; attempt <= WAIT_RETRIES; attempt += 1)); do
    if command -v nc >/dev/null 2>&1; then
      nc -z "$host" "$port" && return 0
    else
      timeout 3 bash -c "cat < /dev/null > /dev/tcp/$host/$port" && return 0
    fi
    sleep "$WAIT_DELAY_SECONDS"
  done
  echo "Timed out waiting for $host:$port" >&2
  return 1
}

if [[ "${1:-}" == "cleanup" ]]; then
  cleanup
  exit 0
fi

trap on_exit EXIT

echo "Checking compose syntax..."
"${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" config >/tmp/honeynet-control-compose-check.yaml
"${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" config >/tmp/honeynet-enterprise-compose-check.yaml
"${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" -f "$ENTERPRISE_FILE" config >/tmp/honeynet-combined-compose-check.yaml

if [[ "$RESET_BEFORE_RUN" == "1" ]]; then
  PROJECT_NAME="$PROJECT_NAME" ./scripts/reset_enterprise_runtime.sh --quiet
fi

echo "Starting control plane..."
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" up -d

echo "Starting enterprise default slice..."
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" up -d "${ENTERPRISE_SERVICES[@]}"

echo "Checking public portal..."
wait_for_host_http "http://${HOST_CHECK_ADDRESS}:${PUBLIC_PORTAL_PORT:-8080}"

echo "Checking Cowrie SSH port..."
wait_for_tcp "$HOST_CHECK_ADDRESS" "${COWRIE_SSH_PORT:-2222}"

echo "Checking control plane is not published to host..."
if curl -fsSI --max-time 2 http://127.0.0.1:8002 >/dev/null 2>&1; then
  echo "profiler unexpectedly reachable from host on 127.0.0.1:8002" >&2
  exit 1
fi

echo "Checking control plane is reachable inside Docker network..."
wait_for_docker_http honeynet_net_control http://profiler:8002/docs
wait_for_docker_http honeynet_net_control http://opencanary-adapter:8012/healthz
wait_for_docker_http honeynet_net_control http://entrypoint-observer:8010/healthz

echo "Compose smoke test passed."
