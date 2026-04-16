from __future__ import annotations

import pytest

from libs.contracts.models import ActionType, ControllerAction, OrchestratorApplyRequest, ResolveBindingRequest
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.orchestrator.domain import OrchestratorService
from services.orchestrator.repository import InMemoryRouteStateRepository


pytestmark = pytest.mark.unit


def test_apply_unlock_updates_binding_assets_and_route_updates() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    orchestrator = OrchestratorService(
        binding_service,
        InMemoryRouteStateRepository(),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.50"))

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="git-internal",
                    reason="unlock git",
                ),
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="git-internal",
                    reason="duplicate unlock",
                ),
            ],
        )
    )

    assert response.binding.unlocked_assets == ["git-internal"]
    assert response.route_updates == [
        f"binding {binding.binding_id} exposes git-internal"
    ]


def test_recycle_then_resolve_keeps_unlocked_assets() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    orchestrator = OrchestratorService(
        binding_service,
        InMemoryRouteStateRepository(),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.51"))
    orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="finance-share",
                    reason="unlock share",
                ),
                ControllerAction(
                    action_type=ActionType.recycle,
                    binding_id=binding.binding_id,
                    reason="idle recycle",
                ),
            ],
        )
    )

    recovered = binding_service.resolve(
        ResolveBindingRequest(attacker_key="198.51.100.51")
    )

    assert recovered.status == "recovered"
    assert recovered.unlocked_assets == ["finance-share"]
