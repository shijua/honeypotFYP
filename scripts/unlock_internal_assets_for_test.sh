#!/usr/bin/env bash
set -euo pipefail

CATALOG_FILE="data/assets/catalog.json"

if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

PROJECT_NAME="${PROJECT_NAME:-honeynet}"
ATTACKER_KEY="${ATTACKER_KEY:-${CLIENT_TARGET_HOST:-${HOST_BIND_ADDRESS:-127.0.0.1}}}"
ASSETS_CSV=""
ALL_CATALOG=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: ./scripts/unlock_internal_assets_for_test.sh [options]

Force-unlocks internal assets for one attacker binding through the normal
orchestrator API. This is a manual test helper; it does not change controller
policy or dependency logic.

Options:
  --attacker-key IP_OR_KEY  Binding attacker_key to unlock for.
  --assets a,b,c            Unlock only this comma-separated asset list.
  --all-catalog             Include every internal catalog asset, even assets
                            without a configured asset-gateway listener.
  --dry-run                 Print the assets/actions without applying them.
  --project-name NAME       Compose project name. Default: honeynet.
  -h, --help                Show this help.

Default behavior unlocks internal Docker assets whose fixed public ports are
served by asset-gateway. This skips internal assets whose public port is not
currently in ASSET_GATEWAY_PORTS.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --attacker-key)
      ATTACKER_KEY="$2"
      shift
      ;;
    --assets)
      ASSETS_CSV="$2"
      shift
      ;;
    --all-catalog)
      ALL_CATALOG=1
      ;;
    --dry-run)
      DRY_RUN=1
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

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required because control-plane APIs are private to ${PROJECT_NAME}_net_control." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to build the test unlock payload." >&2
  exit 1
fi

if [[ ! -f "$CATALOG_FILE" ]]; then
  echo "Missing asset catalog: $CATALOG_FILE" >&2
  exit 1
fi

CONTROL_NETWORK="${PROJECT_NAME}_net_control"
ASSET_GATEWAY_PORTS="${ASSET_GATEWAY_PORTS:-18080,19418,13306,16379,18081,12121,12222,12323,2525,18082,18443,18085}"

docker_post_json() {
  local url="$1"
  docker run --rm -i --network "$CONTROL_NETWORK" curlimages/curl:latest \
    -fsS -H "Content-Type: application/json" --data-binary @- "$url"
}

docker_get() {
  local url="$1"
  docker run --rm --network "$CONTROL_NETWORK" curlimages/curl:latest -fsS "$url"
}

if [[ -n "$ASSETS_CSV" ]]; then
  asset_ids_json="$(
    printf '%s' "$ASSETS_CSV" |
      jq -Rc 'split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))'
  )"
elif [[ "$ALL_CATALOG" == "1" ]]; then
  asset_ids_json="$(
    jq -c '[.[] | select(.exposure_type == "internal") | .asset_id]' "$CATALOG_FILE"
  )"
else
  asset_ids_json="$(
    jq -c --arg ports "$ASSET_GATEWAY_PORTS" '
      ($ports | split(",") | map(tonumber?)) as $gateway_ports
      | [
          .[]
          | select(.exposure_type == "internal")
          | select((.default_settings.runtime.backend // "") == "docker")
          | select((.telemetry_source // "") != "high_interaction")
          | . as $asset
          | (
              ($asset.default_settings.runtime.port_mappings // [])
              | map(.requested_host_port // .container_port)
              | map(select(. as $port | $gateway_ports | index($port)))
            ) as $matching_ports
          | select(($matching_ports | length) > 0)
          | $asset.asset_id
        ]
    ' "$CATALOG_FILE"
  )"
fi

if [[ "$(jq 'length' <<<"$asset_ids_json")" -eq 0 ]]; then
  echo "No matching internal assets selected." >&2
  exit 1
fi

echo "Test attacker_key: $ATTACKER_KEY"
echo "Selected assets:"
jq -r '.[] | "  - " + .' <<<"$asset_ids_json"

binding_response="$(
  jq -n --arg attacker_key "$ATTACKER_KEY" \
    '{attacker_key: $attacker_key, protocol: "tcp"}' |
    docker_post_json "http://binding-service:8001/v1/bindings/resolve"
)"
binding_id="$(jq -r '.binding_id' <<<"$binding_response")"
unlocked_assets="$(jq -c '.unlocked_assets // []' <<<"$binding_response")"

actions_json="$(
  jq -n \
    --arg binding_id "$binding_id" \
    --argjson asset_ids "$asset_ids_json" \
    --argjson unlocked "$unlocked_assets" '
      $asset_ids
      | map(select(. as $asset_id | ($unlocked | index($asset_id) | not)))
      | map({
          action_type: "unlock",
          binding_id: $binding_id,
          asset_id: .,
          reason: "manual test-mode unlock"
        })
    '
)"

echo "Binding: $binding_id"
echo "Already unlocked:"
jq -r '.[]? | "  - " + .' <<<"$unlocked_assets"

if [[ "$(jq 'length' <<<"$actions_json")" -eq 0 ]]; then
  echo "All selected assets were already unlocked for this binding."
  docker_get "http://gateway:8004/v1/gateway/bindings/$binding_id" | jq
  exit 0
fi

echo "Actions to apply:"
jq -r '.[] | "  - " + .asset_id' <<<"$actions_json"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "Dry run only; no actions applied."
  exit 0
fi

apply_response="$(
  jq -n --arg binding_id "$binding_id" --argjson actions "$actions_json" \
    '{binding_id: $binding_id, actions: $actions}' |
    docker_post_json "http://orchestrator:8005/v1/orchestration/apply"
)"

echo
echo "Unlocked assets:"
jq -r '.binding.unlocked_assets[]? | "  - " + .' <<<"$apply_response"

echo
echo "Runtime events:"
jq -r '.runtime_events[]? | "  - " + .asset_id + " [" + .status + "]"' <<<"$apply_response"

echo
echo "Gateway state:"
docker_get "http://gateway:8004/v1/gateway/bindings/$binding_id" |
  jq '{binding_id, attacker_key, exposed_assets, failed_assets, route_updates}'

echo
echo "Asset gateway routes for this attacker:"
jq --arg attacker_key "$ATTACKER_KEY" \
  '.routes | map(select(.attacker_key == $attacker_key))' \
  data/runtime/asset_gateway_routes.json
