from __future__ import annotations

import pytest
from pydantic import ValidationError

from libs.contracts.models import BindingRecord, ResolveBindingRequest
from services.binding_service.app import app


pytestmark = pytest.mark.contract


def test_resolve_binding_request_rejects_empty_attacker_key() -> None:
    # Contract guard: attacker_key is required and cannot be empty.
    with pytest.raises(ValidationError):
        ResolveBindingRequest(attacker_key="", protocol="ssh")


def test_binding_record_has_schema_version() -> None:
    # All serialized payloads must carry explicit schema_version.
    record = BindingRecord.model_validate(
        {
            "binding_id": "b-1",
            "attacker_key": "198.51.100.10",
            "backend_instance_id": "ns-b-1",
            "status": "active",
            "first_seen_ts": "2026-01-01T00:00:00Z",
            "last_seen_ts": "2026-01-01T00:00:00Z",
            "ttl_expires_at": "2026-01-08T00:00:00Z",
        }
    )
    dumped = record.model_dump()

    assert dumped["schema_version"] == "v1"


def test_openapi_contains_binding_paths() -> None:
    # OpenAPI must expose the binding lifecycle endpoints.
    schema = app.openapi()

    assert "/v1/bindings/resolve" in schema["paths"]
    assert "/v1/bindings/{binding_id}/heartbeat" in schema["paths"]
    assert "/v1/bindings/{binding_id}/recycle" in schema["paths"]
