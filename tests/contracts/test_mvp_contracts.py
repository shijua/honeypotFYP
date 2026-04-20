from __future__ import annotations

import pytest
from pydantic import ValidationError

from libs.contracts.models import (
    ControllerTickResponse,
    CowrieIngestRequest,
    EntrypointCaptureRequest,
    EvidenceIngestRequest,
    GatewaySyncRequest,
    OrchestratorApplyRequest,
)
from services.controller.app import app as controller_app
from services.cowrie.app import app as cowrie_app
from services.entrypoint.app import app as entrypoint_app
from services.gateway.app import app as gateway_app
from services.orchestrator.app import app as orchestrator_app
from services.profiler.app import app as profiler_app


pytestmark = pytest.mark.contract


def test_evidence_ingest_request_requires_binding_id() -> None:
    with pytest.raises(ValidationError):
        EvidenceIngestRequest(
            attacker_key="198.51.100.70",
            binding_id="",
            event={
                "ts": "2026-01-01T00:00:00Z",
                "falco_rule": "Read sensitive file",
                "priority": "WARNING",
                "output": "Sensitive file read /etc/shadow",
            },
        )


def test_controller_tick_response_has_schema_version() -> None:
    response = ControllerTickResponse(binding_id="binding-7")
    dumped = response.model_dump()

    assert dumped["schema_version"] == "v1"


def test_orchestrator_apply_request_requires_binding_id() -> None:
    with pytest.raises(ValidationError):
        OrchestratorApplyRequest(binding_id="")


def test_gateway_sync_request_requires_binding_payload() -> None:
    with pytest.raises(ValidationError):
        GatewaySyncRequest(binding={})


def test_entrypoint_capture_request_requires_attacker_key() -> None:
    with pytest.raises(ValidationError):
        EntrypointCaptureRequest(
            attacker_key="",
            method="GET",
            path="/",
        )


def test_cowrie_ingest_request_requires_event_payload() -> None:
    with pytest.raises(ValidationError):
        CowrieIngestRequest(event={})


def test_openapi_contains_new_mvp_paths() -> None:
    assert "/v1/evidence/ingest" in profiler_app.openapi()["paths"]
    assert "/v1/controller/tick" in controller_app.openapi()["paths"]
    assert "/v1/orchestration/apply" in orchestrator_app.openapi()["paths"]
    assert "/v1/gateway/sync" in gateway_app.openapi()["paths"]
    assert "/healthz" in entrypoint_app.openapi()["paths"]
    assert "/v1/cowrie/events" in cowrie_app.openapi()["paths"]
