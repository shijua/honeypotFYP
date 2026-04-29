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
if [[ -z "${HOST_PROJECT_ROOT:-}" || "${HOST_PROJECT_ROOT:-}" == "." ]]; then
  HOST_PROJECT_ROOT="$PWD"
elif [[ "$HOST_PROJECT_ROOT" != /* ]]; then
  # Docker bind mounts need an absolute host path, not a path relative to the
  # caller's current shell.
  HOST_PROJECT_ROOT="$(cd "$HOST_PROJECT_ROOT" && pwd)"
fi

merge_asset_gateway_ports() {
  # The asset gateway exposes fixed public ports. Merge env overrides with the
  # catalog defaults so each listener starts once even if a port appears twice.
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
    "${ICS_PLC_PORT:-18084}" \
    "${VPN_APPLIANCE_PORT:-18443}" \
    "${MALWARE_SINK_PORT:-18085}"
)"
export PROJECT_NAME HOST_PROJECT_ROOT ASSET_GATEWAY_PORTS
RESET_BEFORE_START="${RESET_BEFORE_START:-1}"
KEEP_STATE=0
WAIT_FOR_SERVICES=1
WAIT_RETRIES="${WAIT_RETRIES:-60}"
WAIT_DELAY_SECONDS="${WAIT_DELAY_SECONDS:-2}"
ENABLE_WEB_CLONE="${ENABLE_WEB_CLONE:-0}"
ENTERPRISE_SERVICES=(
  public-portal
  public-portal-forwarder
  asset-gateway
  cowrie
  opencanary-adapter
  opencanary-forwarder
  entrypoint-observer
  cowrie-adapter
  cowrie-forwarder
  internal-portal
)

usage() {
  cat <<'EOF'
Usage: ./scripts/start_enterprise_stack.sh [options]

Starts the control plane and enterprise slice without generating attacker traffic.

Options:
  --no-reset       Do not stop containers or clear runtime state before starting.
  --keep-state     Stop/recreate containers but preserve data/runtime JSON state.
  --no-wait        Do not wait for HTTP health checks.
  --with-web-clone Start optional SNARE/TANNER web clone services.
  --project-name   Compose project name. Default: honeynet.
  -h, --help       Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-reset)
      RESET_BEFORE_START=0
      ;;
    --keep-state)
      KEEP_STATE=1
      ;;
    --no-wait)
      WAIT_FOR_SERVICES=0
      ;;
    --with-web-clone)
      ENABLE_WEB_CLONE=1
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
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

echo "Checking compose syntax..."
"${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" config >/tmp/honeynet-control-compose-check.yaml
"${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" config >/tmp/honeynet-enterprise-compose-check.yaml

if [[ "$RESET_BEFORE_START" == "1" ]]; then
  reset_args=(--quiet --project-name "$PROJECT_NAME")
  if [[ "$KEEP_STATE" == "1" ]]; then
    reset_args+=(--keep-state)
  fi
  echo "Resetting runtime before start..."
  ./scripts/reset_enterprise_runtime.sh "${reset_args[@]}"
fi

echo "Starting control plane..."
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$CONTROL_FILE" up -d

echo "Starting enterprise slice..."
if [[ "$ENABLE_WEB_CLONE" == "1" ]]; then
  ENTERPRISE_SERVICES+=(tanner snare)
fi
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" up -d "${ENTERPRISE_SERVICES[@]}"

if [[ "$WAIT_FOR_SERVICES" == "1" ]]; then
  echo "Waiting for services..."
  wait_for_tcp "${CLIENT_TARGET_HOST:-127.0.0.1}" "${PUBLIC_PORTAL_PORT:-8080}"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://dashboard:8090/healthz"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://profiler:8002/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://controller:8003/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://orchestrator:8005/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://gateway:8004/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://cowrie-adapter:8011/healthz"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://opencanary-adapter:8012/healthz"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://entrypoint-observer:8010/healthz"
fi

echo
echo "Enterprise stack is ready for manual testing."
echo "Public portal:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${PUBLIC_PORTAL_PORT:-8080}/"
echo "HTTP observer:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${ENTRYPOINT_OBSERVER_PORT:-8083}/.env"
echo "Dashboard:       http://${CLIENT_TARGET_HOST:-127.0.0.1}:${DASHBOARD_PORT:-8090}/"
echo "Cowrie SSH:      ssh -p ${COWRIE_SSH_PORT:-2222} root@${CLIENT_TARGET_HOST:-127.0.0.1}"
echo "SNARE HTTP:      ./scripts/start_enterprise_stack.sh --with-web-clone to enable http://${CLIENT_TARGET_HOST:-127.0.0.1}:${SNARE_HTTP_PORT:-8081}/"
echo "Adaptive Git:    git://${CLIENT_TARGET_HOST:-127.0.0.1}:${GIT_INTERNAL_PORT:-19418}/ after git-internal unlock"
echo "Adaptive MySQL:  ${CLIENT_TARGET_HOST:-127.0.0.1}:${OPS_DB_PORT:-13306} after ops-db unlock"
echo "Adaptive Redis:  ${CLIENT_TARGET_HOST:-127.0.0.1}:${REDIS_CACHE_PORT:-16379} after redis-cache unlock"
echo "Adaptive Web:    http://${CLIENT_TARGET_HOST:-127.0.0.1}:${WEB_ADMIN_CONSOLE_PORT:-18081}/ after web-admin-console unlock"
echo "Adaptive FTP:    ${CLIENT_TARGET_HOST:-127.0.0.1}:${FTP_ARCHIVE_PORT:-12121} after ftp-archive unlock"
echo "Adaptive SSH:    ssh -p ${SSH_CANARY_PORT:-12222} root@${CLIENT_TARGET_HOST:-127.0.0.1} after ssh-canary unlock"
echo "Adaptive Telnet: telnet ${CLIENT_TARGET_HOST:-127.0.0.1} ${LEGACY_TELNET_PORT:-12323} after legacy-telnet unlock"
echo "Adaptive SMTP:   ${CLIENT_TARGET_HOST:-127.0.0.1}:${MAIL_RELAY_PORT:-2525} after mail-relay unlock"
echo "Finance Share:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${FINANCE_SHARE_PORT:-18082}/ after finance-share unlock"
echo "ICS Panel:       http://${CLIENT_TARGET_HOST:-127.0.0.1}:${ICS_PLC_PORT:-18084}/ after ics-plc unlock"
echo "VPN Appliance:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${VPN_APPLIANCE_PORT:-18443}/ after vpn-appliance unlock"
echo "Malware Sink:    http://${CLIENT_TARGET_HOST:-127.0.0.1}:${MALWARE_SINK_PORT:-18085}/ after malware-sink unlock"
echo "Vulhub asset:    log4shell-app requires vendor/vulhub/log4j/CVE-2021-44228/docker-compose.yml"
echo
echo "For local browser access over SSH tunnel:"
echo "  ssh -N -L 18090:127.0.0.1:${DASHBOARD_PORT:-8090} vm"
