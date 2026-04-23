from __future__ import annotations

import pytest

from libs.contracts.models import BindingStatus, GatewaySyncRequest, ResolveBindingRequest
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.gateway.domain import GatewayService
from services.gateway.repository import InMemoryGatewayRouteRepository


pytestmark = pytest.mark.unit


def test_gateway_sync_tracks_binding_assets_and_route_updates() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.80"))
    updated_binding = binding_service.unlock_assets(binding.binding_id, ["internal-portal"])
    service = GatewayService(InMemoryGatewayRouteRepository())

    response = service.sync(
        GatewaySyncRequest(
            binding=updated_binding,
            route_updates=[f"binding {binding.binding_id} exposes internal-portal"],
        )
    )

    assert response.state.exposed_assets == ["internal-portal"]
    assert response.state.status == BindingStatus.active
    assert response.state.route_updates == [
        f"binding {binding.binding_id} exposes internal-portal"
    ]


def test_gateway_sync_prefers_accessible_asset_override() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.81"))
    updated_binding = binding_service.unlock_assets(
        binding.binding_id,
        ["internal-portal", "redis-cache"],
    )
    service = GatewayService(InMemoryGatewayRouteRepository())

    response = service.sync(
        GatewaySyncRequest(
            binding=updated_binding,
            route_updates=[f"binding {binding.binding_id} exposes internal-portal"],
            exposed_assets_override=["internal-portal"],
        )
    )

    assert response.state.exposed_assets == ["internal-portal"]


def test_gateway_sync_tracks_failed_assets_override() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.82"))
    updated_binding = binding_service.unlock_assets(
        binding.binding_id,
        ["internal-portal", "redis-cache"],
    )
    service = GatewayService(InMemoryGatewayRouteRepository())

    response = service.sync(
        GatewaySyncRequest(
            binding=updated_binding,
            route_updates=[],
            exposed_assets_override=["internal-portal"],
            failed_assets_override=["redis-cache"],
        )
    )

    assert response.state.exposed_assets == ["internal-portal"]
    assert response.state.failed_assets == ["redis-cache"]
