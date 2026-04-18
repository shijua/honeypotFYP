from __future__ import annotations

from libs.common.clock import utcnow
from libs.contracts.models import (
    GatewayBindingState,
    GatewaySyncRequest,
    GatewaySyncResponse,
)
from services.gateway.repository import GatewayRouteRepository


class GatewayStateNotFoundError(KeyError):
    """Raised when a gateway route state does not exist."""

    pass


class GatewayService:
    """Route-state service that mirrors exposed assets per binding."""

    def __init__(self, repository: GatewayRouteRepository) -> None:
        self._repository = repository

    def sync(self, request: GatewaySyncRequest) -> GatewaySyncResponse:
        existing = self._repository.get(request.binding.binding_id)
        route_updates = list(existing.route_updates) if existing else []
        route_updates.extend(request.route_updates)
        state = GatewayBindingState(
            binding_id=request.binding.binding_id,
            attacker_key=request.binding.attacker_key,
            backend_instance_id=request.binding.backend_instance_id,
            status=request.binding.status,
            exposed_assets=list(request.binding.unlocked_assets),
            route_updates=route_updates,
            updated_at=utcnow(),
        )
        return GatewaySyncResponse(state=self._repository.upsert(state))

    def get_state(self, binding_id: str) -> GatewayBindingState:
        state = self._repository.get(binding_id)
        if state is None:
            raise GatewayStateNotFoundError(binding_id)
        return state
