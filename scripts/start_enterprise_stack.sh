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
HOST_PROJECT_ROOT="${HOST_PROJECT_ROOT:-$PWD}"
export PROJECT_NAME HOST_PROJECT_ROOT
RESET_BEFORE_START="${RESET_BEFORE_START:-1}"
KEEP_STATE=0
WAIT_FOR_SERVICES=1
WAIT_RETRIES="${WAIT_RETRIES:-60}"
WAIT_DELAY_SECONDS="${WAIT_DELAY_SECONDS:-2}"

usage() {
  cat <<'EOF'
Usage: ./scripts/start_enterprise_stack.sh [options]

Starts the control plane and enterprise slice without generating attacker traffic.

Options:
  --no-reset       Do not stop containers or clear runtime state before starting.
  --keep-state     Stop/recreate containers but preserve data/runtime JSON state.
  --no-wait        Do not wait for HTTP health checks.
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
COMPOSE_IGNORE_ORPHANS=True "${COMPOSE[@]}" -p "$PROJECT_NAME" -f "$ENTERPRISE_FILE" up -d

if [[ "$WAIT_FOR_SERVICES" == "1" ]]; then
  echo "Waiting for services..."
  wait_for_docker_http "${PROJECT_NAME}_net_public" "http://public-portal/"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://dashboard:8090/healthz"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://profiler:8002/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://controller:8003/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://orchestrator:8005/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://gateway:8004/docs"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://cowrie-adapter:8011/healthz"
  wait_for_docker_http "${PROJECT_NAME}_net_control" "http://entrypoint-observer:8010/healthz"
fi

echo
echo "Enterprise stack is ready for manual testing."
echo "Public portal:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${PUBLIC_PORTAL_PORT:-8080}/"
echo "HTTP observer:   http://${CLIENT_TARGET_HOST:-127.0.0.1}:${ENTRYPOINT_OBSERVER_PORT:-8083}/.env"
echo "Dashboard:       http://${CLIENT_TARGET_HOST:-127.0.0.1}:${DASHBOARD_PORT:-8090}/"
echo "Cowrie SSH:      ssh -p ${COWRIE_SSH_PORT:-2222} root@${CLIENT_TARGET_HOST:-127.0.0.1}"
echo "SNARE HTTP:      http://${CLIENT_TARGET_HOST:-127.0.0.1}:${SNARE_HTTP_PORT:-8081}/"
echo "Chameleon HTTP:  http://${CLIENT_TARGET_HOST:-127.0.0.1}:${CHAMELEON_HTTP_PORT:-8082}/"
echo "Chameleon SSH:   ssh -p ${CHAMELEON_SSH_PORT:-2224} root@${CLIENT_TARGET_HOST:-127.0.0.1}"
echo "Chameleon Redis: ${CLIENT_TARGET_HOST:-127.0.0.1}:${CHAMELEON_REDIS_PORT:-6380}"
echo "Chameleon MySQL: ${CLIENT_TARGET_HOST:-127.0.0.1}:${CHAMELEON_MYSQL_PORT:-3307}"
echo "Vulhub asset:    log4shell-app requires vendor/vulhub/log4j/CVE-2021-44228/docker-compose.yml"
echo
echo "For local browser access over SSH tunnel:"
echo "  ssh -N -L 18090:127.0.0.1:${DASHBOARD_PORT:-8090} vm"
