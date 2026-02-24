from __future__ import annotations

import pytest

from libs.common.clock import utcnow
from libs.contracts.models import HeartbeatRequest, RecycleRequest, ResolveBindingRequest
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository


pytestmark = pytest.mark.unit


def test_resolve_is_sticky_for_same_attacker() -> None:
    # Same attacker_key should keep the same logical binding while active.
    service = BindingService(InMemoryBindingRepository())

    first = service.resolve(ResolveBindingRequest(attacker_key="1.2.3.4", protocol="ssh"))
    second = service.resolve(ResolveBindingRequest(attacker_key="1.2.3.4", protocol="ssh"))

    assert first.binding_id == second.binding_id
    assert second.status == "active"


def test_recycle_then_resolve_marks_recovered() -> None:
    # Idle recycle keeps state; next resolve resumes as recovered.
    service = BindingService(InMemoryBindingRepository())

    record = service.resolve(ResolveBindingRequest(attacker_key="5.6.7.8"))
    recycled = service.recycle(record.binding_id, RecycleRequest(mode="idle"))
    recovered = service.resolve(ResolveBindingRequest(attacker_key="5.6.7.8"))

    assert recycled.status == "recycled"
    assert recovered.binding_id == record.binding_id
    assert recovered.status == "recovered"


def test_heartbeat_refreshes_last_seen() -> None:
    # Heartbeat extends liveness window and returns binding to active.
    service = BindingService(InMemoryBindingRepository())
    record = service.resolve(ResolveBindingRequest(attacker_key="9.9.9.9"))

    ts = utcnow()
    refreshed = service.heartbeat(record.binding_id, HeartbeatRequest(ts=ts))

    assert refreshed.last_seen_ts == ts
    assert refreshed.status == "active"
