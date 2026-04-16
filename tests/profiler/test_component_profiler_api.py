from __future__ import annotations

import pytest


pytestmark = pytest.mark.component


def test_ingest_endpoint_updates_profile(profiler_client) -> None:
    response = profiler_client.post(
        "/v1/evidence/ingest",
        json={
            "attacker_key": "203.0.113.10",
            "binding_id": "binding-1",
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

    assert response.status_code == 200
    body = response.json()
    assert body["evidences"][0]["tech_id"] == "T1003"
    assert body["profile"]["recent_tactics"] == ["Credential Access"]
