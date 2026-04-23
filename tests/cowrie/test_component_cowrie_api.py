from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.component


def test_cowrie_api_ingests_command_event(cowrie_client: TestClient) -> None:
    response = cowrie_client.post(
        "/v1/cowrie/events",
        json={
            "event": {
                "eventid": "cowrie.command.input",
                "timestamp": "2026-01-01T00:00:00Z",
                "src_ip": "198.51.100.213",
                "session": "s-4",
                "input": "totallycustom",
            }
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["observation"]["eventid"] == "cowrie.command.input"
    assert body["profile"]["recent_tactics"] == []
