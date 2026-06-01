from __future__ import annotations

import pytest
from pydantic import ValidationError

from libs.contracts.models import (
    AssetDefinition,
    AssetRuntimeRecord,
    ControllerTickResponse,
    CowrieIngestRequest,
    EntrypointCaptureRequest,
    EvidenceIngestRequest,
    GatewaySyncRequest,
    OpenCanaryIngestRequest,
    OrchestratorApplyRequest,
    OrchestratorApplyResponse,
)
from services.controller.app import app as controller_app
from services.cowrie.app import app as cowrie_app
from services.entrypoint.app import app as entrypoint_app
from services.gateway.app import app as gateway_app
from services.orchestrator.app import app as orchestrator_app
from services.opencanary.app import app as opencanary_app
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
                "priority": "medium",
                "output": "Sensitive file read /etc/shadow",
            },
        )


def test_controller_tick_response_has_schema_version() -> None:
    response = ControllerTickResponse(binding_id="binding-7")
    dumped = response.model_dump()

    assert dumped["schema_version"] == "v1"


def test_asset_definition_accepts_template_metadata() -> None:
    asset = AssetDefinition(
        asset_id="admin-jumpbox",
        asset_name="Admin Jumpbox",
        exposure_type="internal",
        interaction_level="high",
        template_family="ssh-honeypot",
        protocols=["ssh"],
        ports=[22],
        source_refs=["tpotce:cowrie"],
        telemetry_source="cowrie",
        default_settings={
            "hostname": "admin-jumpbox-01",
            "image_references": ["ghcr.io/telekom-security/cowrie:24.04.1"],
        },
        covers_tactics=["Lateral Movement"],
    )

    assert asset.template_family == "ssh-honeypot"
    assert asset.protocols == ["ssh"]
    assert asset.ports == [22]
    assert asset.source_refs == ["tpotce:cowrie"]
    assert asset.telemetry_source == "cowrie"
    assert asset.default_settings["hostname"] == "admin-jumpbox-01"
    assert asset.default_settings["image_references"] == [
        "ghcr.io/telekom-security/cowrie:24.04.1"
    ]


def test_orchestrator_response_accepts_runtime_and_monitoring_events() -> None:
    record = AssetRuntimeRecord(
        runtime_id="runtime-1",
        binding_id="binding-1",
        asset_id="admin-jumpbox",
        asset_name="Admin Jumpbox",
        template_family="ssh-honeypot",
        settings={"hostname": "admin-jumpbox-01"},
    )
    response = OrchestratorApplyResponse(
        binding={
            "binding_id": "binding-1",
            "attacker_key": "198.51.100.10",
            "backend_instance_id": "ns-binding",
            "status": "active",
            "first_seen_ts": "2026-01-01T00:00:00Z",
            "last_seen_ts": "2026-01-01T00:00:00Z",
            "ttl_expires_at": "2026-01-02T00:00:00Z",
        },
        runtime_events=[record],
        monitoring_events=[
            {
                "ts": "2026-01-01T00:00:00Z",
                "falco_rule": "Honeynet asset template started",
                "priority": "low",
                "output": "asset admin-jumpbox started",
                "tags": ["honeynet_asset_runtime"],
            }
        ],
    )

    assert response.runtime_events[0].asset_id == "admin-jumpbox"
    assert response.monitoring_events[0].falco_rule == "Honeynet asset template started"


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


def test_opencanary_ingest_request_requires_event_payload() -> None:
    with pytest.raises(ValidationError):
        OpenCanaryIngestRequest(event={})


def test_openapi_contains_new_mvp_paths() -> None:
    assert "/v1/evidence/ingest" in profiler_app.openapi()["paths"]
    assert "/v1/controller/tick" in controller_app.openapi()["paths"]
    assert "/v1/orchestration/apply" in orchestrator_app.openapi()["paths"]
    assert "/v1/gateway/sync" in gateway_app.openapi()["paths"]
    assert "/healthz" in entrypoint_app.openapi()["paths"]
    assert "/v1/cowrie/events" in cowrie_app.openapi()["paths"]
    assert "/v1/opencanary/events" in opencanary_app.openapi()["paths"]
