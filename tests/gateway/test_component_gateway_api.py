from __future__ import annotations

import pytest


pytestmark = pytest.mark.component


def test_gateway_sync_endpoint_returns_state(gateway_client, binding_client) -> None:
    binding = binding_client.post(
        "/v1/bindings/resolve",
        json={"attacker_key": "198.51.100.81", "protocol": "ssh"},
    ).json()

    response = gateway_client.post(
        "/v1/gateway/sync",
        json={
            "binding": binding,
            "route_updates": [f"binding {binding['binding_id']} exposes internal-portal"],
        },
    )

    assert response.status_code == 200
    assert response.json()["state"]["binding_id"] == binding["binding_id"]
