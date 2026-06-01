#!/usr/bin/env bash
set -euo pipefail

# Operator-side helper for live configuration-variant smoke tests.
#
# This does not simulate attacker traffic. It calls the private control-plane
# APIs to apply one catalog configuration variant to one attacker binding. After
# it finishes, use ATTACK_TESTING_GUIDE.md to probe the attacker-facing port and
# confirm the visible file, banner, route, or backend changed.

CATALOG_FILE="data/assets/catalog.json"

if [[ -f .env ]]; then
  set -a
  . ./.env
  set +a
fi

PROJECT_NAME="${PROJECT_NAME:-honeynet}"
ATTACKER_KEY="${ATTACKER_KEY:-${CLIENT_TARGET_HOST:-${HOST_BIND_ADDRESS:-127.0.0.1}}}"

usage() {
  cat <<'EOF'
Usage: ATTACKER_KEY=IP ./scripts/apply_configuration_variant_for_test.sh ASSET_ID CONFIGURATION_ID

Applies one catalog configuration variant through the normal orchestrator API.
This is an operator-side helper; attacker traffic should still use the public
host and fixed ports from ATTACK_TESTING_GUIDE.md.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 2 ]]; then
  usage
  exit 1
fi

ASSET_ID="$1"
CONFIGURATION_ID="$2"
CONTROL_NETWORK="${PROJECT_NAME}_net_control"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required because control-plane APIs are private to ${CONTROL_NETWORK}." >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to build the configuration payload." >&2
  exit 1
fi

configuration="$(
  # Use the exact catalog variant payload that a controller configure action
  # would carry, instead of hand-writing a test-only request body.
  jq -c --arg asset "$ASSET_ID" --arg config "$CONFIGURATION_ID" '
    .[]
    | select(.asset_id == $asset)
    | .default_settings.configuration_variants[]
    | select(.configuration_id == $config)
  ' "$CATALOG_FILE"
)"

if [[ -z "$configuration" ]]; then
  echo "No configuration variant ${ASSET_ID}:${CONFIGURATION_ID} in ${CATALOG_FILE}." >&2
  exit 1
fi

docker_post_json() {
  local url="$1"
  docker run --rm -i --network "$CONTROL_NETWORK" curlimages/curl:latest \
    -fsS -H "Content-Type: application/json" --data-binary @- "$url"
}

binding_response="$(
  # Resolve the normal sticky binding for this attacker key. The API is only on
  # the Docker control network, so curl runs in a short-lived control container.
  jq -n --arg attacker_key "$ATTACKER_KEY" \
    '{attacker_key: $attacker_key, protocol: "tcp"}' |
    docker_post_json "http://binding-service:8001/v1/bindings/resolve"
)"
binding_id="$(jq -r '.binding_id' <<<"$binding_response")"
unlocked_assets="$(jq -c '.unlocked_assets // []' <<<"$binding_response")"

actions_json="$(
  # A configuration applies to an already visible asset. If the base asset is
  # not open yet, add the prerequisite unlock before the configure action.
  jq -n \
    --arg binding_id "$binding_id" \
    --arg asset_id "$ASSET_ID" \
    --arg configuration_id "$CONFIGURATION_ID" \
    --argjson configuration "$configuration" \
    --argjson unlocked "$unlocked_assets" '
      (
        if ($unlocked | index($asset_id)) then
          []
        else
          [{
            action_type: "unlock",
            binding_id: $binding_id,
            asset_id: $asset_id,
            reason: "manual configuration smoke prerequisite unlock"
          }]
        end
      )
      + [{
          action_type: "configure",
          binding_id: $binding_id,
          asset_id: $asset_id,
          configuration_id: $configuration_id,
          target_asset_id: ($configuration.target_asset_id // null),
          configuration: $configuration,
          reason: "manual configuration variant smoke"
        }]
    '
)"

apply_response="$(
  # Use the real orchestrator path so HTTP file materialization, target-runtime
  # swaps, route updates, and audit records behave exactly as they do in runtime.
  jq -n --arg binding_id "$binding_id" --argjson actions "$actions_json" \
    '{binding_id: $binding_id, actions: $actions}' |
    docker_post_json "http://orchestrator:8005/v1/orchestration/apply"
)"

# Print the route/runtime fields needed for smoke debugging; the actual
# attacker-visible verification still happens with the guide's probe commands.
echo "Binding: ${binding_id}"
echo "Applied ${ASSET_ID}:${CONFIGURATION_ID}"
jq '{route_updates, runtime_events: [.runtime_events[]? | {asset_id, status, image: .settings.image, configured_runtime: .settings.configured_runtime, public_port: .settings.public_port, backend_host: .settings.backend_host, backend_port: .settings.backend_port}]}' <<<"$apply_response"
