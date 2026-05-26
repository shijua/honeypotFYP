from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


pytestmark = pytest.mark.component


def test_entrypoint_captures_arbitrary_http_path(entrypoint_client: TestClient) -> None:
    response = entrypoint_client.post(
        "/wp-login.php?redirect_to=/wp-admin",
        headers={
            "user-agent": "curl/8.0",
            "authorization": "Bearer secret",
        },
        content=b"log=admin&pwd=hunter2",
    )

    assert response.status_code == 404
    assert response.text == "Not Found\n"


def test_entrypoint_healthz_is_not_captured(entrypoint_client: TestClient) -> None:
    response = entrypoint_client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_entrypoint_ingests_normalized_public_portal_event(
    entrypoint_client: TestClient,
) -> None:
    response = entrypoint_client.post(
        "/v1/entrypoint/events",
        json={
            "attacker_key": "198.51.100.10",
            "method": "GET",
            "path": "/.env.old",
            "query_string": "",
            "headers": {"user-agent": "curl/8.0"},
            "protocol": "http",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["observation"]["path"] == "/.env.old"
    assert payload["observation"]["attacker_key"] == "198.51.100.10"
    assert payload["observation"]["matched_rules"] == [
        "public_http_credential_discovery"
    ]
    assert payload["profile"]["attacker_key"] == "198.51.100.10"
    assert payload["profile"]["recent_techniques"] == ["T1552.001"]


def test_entrypoint_ingests_normalized_internal_asset_event(
    entrypoint_client: TestClient,
) -> None:
    response = entrypoint_client.post(
        "/v1/entrypoint/events",
        json={
            "attacker_key": "198.51.100.11",
            "method": "GET",
            "path": "/downloads/agent-update.bin",
            "query_string": "",
            "headers": {"user-agent": "curl/8.0"},
            "protocol": "http",
            "surface": "internal",
            "asset_id": "malware-sink",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["observation"]["surface"] == "internal"
    assert payload["observation"]["asset_id"] == "malware-sink"
    assert payload["observation"]["matched_rules"] == [
        "internal_http_package_transfer",
    ]
    assert payload["profile"]["recent_techniques"] == ["T1105"]
    assert payload["profile"]["recent_internal_http_paths"] == [
        "/downloads/agent-update.bin"
    ]
