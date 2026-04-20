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
