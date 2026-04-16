from __future__ import annotations

import pytest


pytestmark = pytest.mark.component


def test_controller_tick_returns_unlock_action(controller_client) -> None:
    response = controller_client.post(
        "/v1/controller/tick",
        json={
            "attacker_key": "198.51.100.40",
            "binding_id": "binding-4",
            "profile": {
                "attacker_key": "198.51.100.40",
                "conf_by_tactic": {"Credential Access": 0.9},
                "recent_tactics": ["Credential Access"],
                "recent_evidence_ids": ["e-3"],
            },
            "unlocked_asset_ids": [],
            "assets": [
                {
                    "asset_id": "asset-exploit",
                    "asset_name": "Credential Cache",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Credential Access"],
                    "dependencies": [],
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["actions"][0]["action_type"] == "unlock"
