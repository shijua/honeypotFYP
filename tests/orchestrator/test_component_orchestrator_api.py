from __future__ import annotations

import pytest


pytestmark = pytest.mark.component


def test_orchestrator_apply_endpoint_updates_binding(mvp_clients) -> None:
    binding = mvp_clients["binding"]
    orchestrator = mvp_clients["orchestrator"]

    resolved = binding.post(
        "/v1/bindings/resolve",
        json={"attacker_key": "198.51.100.60", "protocol": "ssh"},
    ).json()
    response = orchestrator.post(
        "/v1/orchestration/apply",
        json={
            "binding_id": resolved["binding_id"],
            "actions": [
                {
                    "action_type": "unlock",
                    "binding_id": resolved["binding_id"],
                    "asset_id": "internal-portal",
                    "reason": "unlock portal",
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["binding"]["unlocked_assets"] == ["internal-portal"]
