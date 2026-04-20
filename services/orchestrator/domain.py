"""Execution layer for controller actions.

This module turns controller decisions into concrete state changes on bindings
and route updates on the gateway view.
"""

from __future__ import annotations

from libs.contracts.models import (
    ActionType,
    BindingRecord,
    GatewaySyncRequest,
    OrchestratorApplyRequest,
    OrchestratorApplyResponse,
    RecycleRequest,
)
from services.binding_service.domain import BindingService
from services.gateway.domain import GatewayService


class OrchestratorService:
    """Mock orchestrator that applies controller actions to binding state.

    Example:
        apply([unlock git-internal]) -> binding.unlocked_assets includes "git-internal"
    """

    def __init__(
        self,
        binding_service: BindingService,
        gateway_service: GatewayService,
    ) -> None:
        self._binding_service = binding_service
        self._gateway_service = gateway_service

    def apply(self, request: OrchestratorApplyRequest) -> OrchestratorApplyResponse:
        binding = self._binding_service.get(request.binding_id)
        route_updates: list[str] = []

        # Apply actions in order.
        for action in request.actions:
            if action.action_type == ActionType.unlock and action.asset_id:
                binding, unlock_route_updates = self._apply_unlocks(
                    binding=binding,
                    binding_id=request.binding_id,
                    asset_ids=[action.asset_id],
                )
                route_updates.extend(unlock_route_updates)
            elif action.action_type == ActionType.route_update:
                route_update = (
                    f"binding {request.binding_id} route update: {action.reason}"
                )
                route_updates.append(route_update)
            elif action.action_type == ActionType.recycle:
                binding = self._binding_service.recycle(
                    request.binding_id,
                    RecycleRequest(mode="idle"),
                )
                route_updates.append(f"binding {request.binding_id} recycled")

        self._gateway_service.sync(
            GatewaySyncRequest(binding=binding, route_updates=route_updates)
        )

        return OrchestratorApplyResponse(
            binding=binding,
            applied_actions=request.actions,
            route_updates=route_updates,
        )

    def _apply_unlocks(
        self,
        binding: BindingRecord,
        binding_id: str,
        asset_ids: list[str],
    ) -> tuple[BindingRecord, list[str]]:
        previous_assets = list(binding.unlocked_assets)
        updated = self._binding_service.unlock_assets(binding_id, asset_ids)
        # Only newly exposed assets generate route updates.
        new_assets = [
            asset_id
            for asset_id in updated.unlocked_assets
            if asset_id not in previous_assets
        ]

        route_updates = []
        for asset_id in new_assets:
            route_update = f"binding {binding_id} exposes {asset_id}"
            route_updates.append(route_update)

        return updated, route_updates
