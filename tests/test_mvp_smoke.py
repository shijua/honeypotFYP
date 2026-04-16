from __future__ import annotations

import pytest


pytestmark = pytest.mark.e2e_smoke


def test_mvp_closes_the_loop_from_binding_to_unlock(mvp_clients) -> None:
    binding_client = mvp_clients["binding"]
    profiler_client = mvp_clients["profiler"]
    controller_client = mvp_clients["controller"]
    orchestrator_client = mvp_clients["orchestrator"]
    attacker_key = "203.0.113.200"

    resolved = binding_client.post(
        "/v1/bindings/resolve",
        json={"attacker_key": attacker_key, "protocol": "ssh"},
    )
    assert resolved.status_code == 200
    binding = resolved.json()

    ingested = profiler_client.post(
        "/v1/evidence/ingest",
        json={
            "attacker_key": attacker_key,
            "binding_id": binding["binding_id"],
            "event": {
                "ts": "2026-01-01T00:00:00Z",
                "falco_rule": "Read sensitive file",
                "priority": "WARNING",
                "output": "Sensitive file read /etc/shadow",
                "tags": ["mitre_credential_access", "T1003"],
                "output_fields": {"proc_cmdline": "cat /etc/shadow"},
            },
        },
    )
    assert ingested.status_code == 200

    profile = profiler_client.get(f"/v1/profiles/{attacker_key}")
    assert profile.status_code == 200

    first_tick = controller_client.post(
        "/v1/controller/tick",
        json={
            "attacker_key": attacker_key,
            "binding_id": binding["binding_id"],
            "profile": profile.json(),
            "unlocked_asset_ids": [],
        },
    )
    assert first_tick.status_code == 200

    first_apply = orchestrator_client.post(
        "/v1/orchestration/apply",
        json={
            "binding_id": binding["binding_id"],
            "actions": first_tick.json()["actions"],
        },
    )
    assert first_apply.status_code == 200
    assert first_apply.json()["binding"]["unlocked_assets"] == ["internal-portal"]

    second_tick = controller_client.post(
        "/v1/controller/tick",
        json={
            "attacker_key": attacker_key,
            "binding_id": binding["binding_id"],
            "profile": profile.json(),
            "unlocked_asset_ids": ["internal-portal"],
        },
    )
    assert second_tick.status_code == 200

    second_apply = orchestrator_client.post(
        "/v1/orchestration/apply",
        json={
            "binding_id": binding["binding_id"],
            "actions": second_tick.json()["actions"],
        },
    )
    assert second_apply.status_code == 200
    assert "finance-share" in second_apply.json()["binding"]["unlocked_assets"]
