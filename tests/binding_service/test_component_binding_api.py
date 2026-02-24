from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.component


def test_resolve_endpoint_is_sticky(binding_client: TestClient) -> None:
    # API-level sticky behavior: same attacker resolves to same binding_id.
    first = binding_client.post(
        "/v1/bindings/resolve",
        json={"attacker_key": "198.51.100.10", "protocol": "ssh"},
    )
    second = binding_client.post(
        "/v1/bindings/resolve",
        json={"attacker_key": "198.51.100.10", "protocol": "ssh"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["binding_id"] == second.json()["binding_id"]


def test_recycle_then_heartbeat(binding_client: TestClient) -> None:
    # Recycle flips status to recycled; heartbeat reactivates the binding.
    resolved = binding_client.post(
        "/v1/bindings/resolve",
        json={"attacker_key": "203.0.113.1", "protocol": "tcp"},
    ).json()

    recycled = binding_client.post(
        f"/v1/bindings/{resolved['binding_id']}/recycle",
        json={"mode": "idle"},
    )
    heartbeat = binding_client.post(
        f"/v1/bindings/{resolved['binding_id']}/heartbeat",
        json={},
    )

    assert recycled.status_code == 200
    assert recycled.json()["status"] == "recycled"
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "active"
