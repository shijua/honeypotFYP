"""Execution layer for controller actions.

This module is where controller decisions become concrete runtime effects:
binding unlock state, gateway exposure updates, and template runtime lifecycle.
"""

from __future__ import annotations

from libs.common.clock import utcnow
from libs.contracts.models import (
    ActionType,
    AssetDefinition,
    AssetRuntimeRecord,
    BindingRecord,
    FalcoEvent,
    GatewaySyncRequest,
    OrchestratorApplyRequest,
    OrchestratorApplyResponse,
    RecycleRequest,
)
from services.binding_service.domain import BindingService
from services.controller.repository import AssetRepository
from services.gateway.domain import GatewayService
from services.orchestrator.template_runtime import HybridTemplateRuntime


class OrchestratorService:
    """Apply controller actions to binding, gateway, and template runtime state.

    Example:
        apply([unlock git-internal]) -> binding.unlocked_assets includes "git-internal"
    """

    def __init__(
        self,
        binding_service: BindingService,
        gateway_service: GatewayService,
        asset_repository: AssetRepository | None = None,
        template_runtime: HybridTemplateRuntime | None = None,
    ) -> None:
        self._binding_service = binding_service
        self._gateway_service = gateway_service
        self._asset_repository = asset_repository
        self._template_runtime = template_runtime

    def apply(self, request: OrchestratorApplyRequest) -> OrchestratorApplyResponse:
        """Apply actions in order and return the updated runtime picture."""
        binding = self._binding_service.get(request.binding_id)
        route_updates: list[str] = []
        runtime_events: list[AssetRuntimeRecord] = []
        monitoring_events: list[FalcoEvent] = []

        # Action ordering matters because earlier unlocks change later state.
        for action in request.actions:
            if action.action_type == ActionType.unlock and action.asset_id:
                binding, unlock_route_updates = self._apply_unlocks(
                    binding=binding,
                    binding_id=request.binding_id,
                    asset_ids=[action.asset_id],
                )
                route_updates.extend(unlock_route_updates)
                for asset_id in _new_asset_ids_from_route_updates(unlock_route_updates):
                    runtime_record = self._start_asset_runtime(binding, asset_id)
                    if runtime_record is not None:
                        runtime_events.append(runtime_record)
                        monitoring_events.append(
                            self._template_runtime.monitoring_event_for(runtime_record)
                        )
            elif action.action_type == ActionType.route_update:
                route_update = (
                    f"binding {request.binding_id} route update: {action.reason}"
                )
                route_updates.append(route_update)
            elif action.action_type == ActionType.recycle:
                stopped_records = self._stop_binding_runtime(request.binding_id)
                runtime_events.extend(stopped_records)
                monitoring_events.extend(_stopped_monitoring_events(stopped_records))
                binding = self._binding_service.recycle(
                    request.binding_id,
                    RecycleRequest(mode="idle"),
                )
                route_updates.append(f"binding {request.binding_id} recycled")

        self._gateway_service.sync(
            GatewaySyncRequest(
                binding=binding,
                route_updates=route_updates,
                exposed_assets_override=self._accessible_asset_ids(binding.binding_id, binding),
                failed_assets_override=self._failed_asset_ids(binding.binding_id),
            )
        )

        return OrchestratorApplyResponse(
            binding=binding,
            applied_actions=request.actions,
            route_updates=route_updates,
            runtime_events=runtime_events,
            monitoring_events=monitoring_events,
        )

    def _apply_unlocks(
        self,
        binding: BindingRecord,
        binding_id: str,
        asset_ids: list[str],
    ) -> tuple[BindingRecord, list[str]]:
        """Persist newly unlocked assets and produce route update strings."""
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

    def _start_asset_runtime(
        self,
        binding: BindingRecord,
        asset_id: str,
    ) -> AssetRuntimeRecord | None:
        """Start runtime state for one unlocked asset when runtime support exists."""
        if self._asset_repository is None or self._template_runtime is None:
            return None

        asset = self._asset_by_id(asset_id)
        if asset is None:
            return None
        return self._template_runtime.start_asset(
            binding.binding_id,
            asset,
            attacker_key=binding.attacker_key,
        )

    def _asset_by_id(self, asset_id: str) -> AssetDefinition | None:
        """Resolve one asset definition from the controller asset catalog."""
        if self._asset_repository is None:
            return None
        for asset in self._asset_repository.list_all():
            if asset.asset_id == asset_id:
                return asset
        return None

    def _stop_binding_runtime(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop any running template runtime records for this binding."""
        if self._template_runtime is None:
            return []
        return self._template_runtime.stop_binding_assets(binding_id)

    def _accessible_asset_ids(
        self,
        binding_id: str,
        binding: BindingRecord,
    ) -> list[str]:
        """Return assets that should be treated as reachable by the gateway.

        Default MVP rule:
        - without runtime support, exposed == unlocked
        - mock runtimes are reachable while marked running
        - Docker runtimes are reachable only while the container is currently Up
        """
        if self._template_runtime is None:
            return list(binding.unlocked_assets)
        return self._template_runtime.list_accessible_asset_ids(binding_id)

    def _failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return assets that were unlocked but whose runtime is currently failed."""
        if self._template_runtime is None:
            return []
        return self._template_runtime.list_failed_asset_ids(binding_id)


def _new_asset_ids_from_route_updates(route_updates: list[str]) -> list[str]:
    """Extract just the asset ids from route update strings."""
    asset_ids = []
    for route_update in route_updates:
        if " exposes " not in route_update:
            continue
        asset_ids.append(route_update.rsplit(" exposes ", 1)[1])
    return asset_ids


def _stopped_monitoring_events(records: list[AssetRuntimeRecord]) -> list[FalcoEvent]:
    """Emit Falco-style stop events for records stopped during recycle."""
    events: list[FalcoEvent] = []
    for record in records:
        events.append(
            FalcoEvent(
                ts=utcnow(),
                falco_rule="Honeynet asset template stopped",
                priority="INFO",
                output=(
                    f"asset {record.asset_id} stopped for binding {record.binding_id} "
                    f"template_family={record.template_family or 'unknown'}"
                ),
                tags=["honeynet_asset_runtime"],
                output_fields={
                    "binding_id": record.binding_id,
                    "asset_id": record.asset_id,
                    "asset_name": record.asset_name,
                    "template_family": record.template_family,
                    "status": record.status,
                    "protocols": record.protocols,
                    "ports": record.ports,
                    "settings": record.settings,
                    "source_refs": record.source_refs,
                },
            )
        )
    return events
