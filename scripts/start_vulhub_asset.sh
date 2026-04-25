#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="${PROJECT_NAME:-honeynet}"
VULHUB_ROOT="${VULHUB_ROOT:-vendor/vulhub}"
VULHUB_SCENARIO="${VULHUB_SCENARIO:-}"
ATTACH_INTERNAL_NETWORK=1

usage() {
  cat <<'EOF'
Usage: ./scripts/start_vulhub_asset.sh --scenario <category/CVE-dir> [options]

Starts one locally cloned Vulhub scenario and optionally attaches its containers to the honeynet internal network.

Options:
  --scenario       Vulhub scenario path under VULHUB_ROOT, for example spring/CVE-2022-22947.
  --root           Local Vulhub checkout. Default: vendor/vulhub.
  --project-name   Honeynet compose project name. Default: honeynet.
  --no-attach      Do not connect scenario containers to <project>_net_internal.
  -h, --help       Show this help.

The script does not clone Vulhub or download scenario files. Clone Vulhub separately and keep high-interaction vulnerable assets isolated.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario)
      VULHUB_SCENARIO="$2"
      shift
      ;;
    --root)
      VULHUB_ROOT="$2"
      shift
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    --no-attach)
      ATTACH_INTERNAL_NETWORK=0
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

if [[ -z "$VULHUB_SCENARIO" ]]; then
  echo "Missing --scenario. Example: --scenario spring/CVE-2022-22947" >&2
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "Docker Compose is not available. Install the Docker Compose plugin or docker-compose." >&2
  exit 1
fi

scenario_dir="$VULHUB_ROOT/$VULHUB_SCENARIO"
if [[ ! -d "$scenario_dir" ]]; then
  echo "Vulhub scenario directory not found: $scenario_dir" >&2
  exit 1
fi

compose_file=""
for candidate in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
  if [[ -f "$scenario_dir/$candidate" ]]; then
    compose_file="$scenario_dir/$candidate"
    break
  fi
done

if [[ -z "$compose_file" ]]; then
  echo "No compose file found in $scenario_dir" >&2
  exit 1
fi

vulhub_project="${PROJECT_NAME}-vulhub"
internal_network="${PROJECT_NAME}_net_internal"

echo "Starting Vulhub scenario $VULHUB_SCENARIO..."
"${COMPOSE[@]}" -p "$vulhub_project" -f "$compose_file" up -d

if [[ "$ATTACH_INTERNAL_NETWORK" == "1" ]]; then
  if ! docker network inspect "$internal_network" >/dev/null 2>&1; then
    echo "Internal network $internal_network does not exist. Start the enterprise stack first or rerun with --no-attach." >&2
    exit 1
  fi

  echo "Attaching Vulhub containers to $internal_network..."
  for container_id in $("${COMPOSE[@]}" -p "$vulhub_project" -f "$compose_file" ps -q); do
    if docker inspect "$container_id" --format '{{json .NetworkSettings.Networks}}' | grep -q "\"$internal_network\""; then
      continue
    fi
    docker network connect "$internal_network" "$container_id"
  done
fi

echo
echo "Vulhub scenario is running under compose project $vulhub_project."
echo "Review published ports with:"
echo "  docker ps --filter name=$vulhub_project"
