from __future__ import annotations

import services.orchestrator.template_runtime as template_runtime_module
import pytest

from libs.contracts.models import (
    ActionType,
    AssetDefinition,
    ControllerAction,
    OrchestratorApplyRequest,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.controller.repository import InMemoryAssetRepository
from services.gateway.domain import GatewayService
from services.gateway.repository import InMemoryGatewayRouteRepository
from services.orchestrator.domain import OrchestratorService
from services.orchestrator.template_runtime import (
    DockerTemplateRuntime,
    _resolve_host_port,
    InMemoryTemplateRuntimeRepository,
    MockTemplateRuntime,
)


pytestmark = pytest.mark.unit


def test_apply_unlock_updates_binding_assets_and_route_updates() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
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
    gateway_state = gateway_service.get_state(binding.binding_id)
    assert gateway_state.exposed_assets == ["git-internal"]


def test_apply_unlock_starts_asset_with_default_settings_and_monitoring_event() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
        InMemoryAssetRepository(
            [
                AssetDefinition(
                    asset_id="admin-jumpbox",
                    asset_name="Admin Jumpbox",
                    exposure_type="internal",
                    interaction_level="high",
                    template_family="ssh-honeypot",
                    protocols=["ssh"],
                    ports=[22],
                    source_refs=["tpotce:cowrie"],
                    default_settings={
                        "hostname": "admin-jumpbox-01",
                        "ssh_banner": "SSH-2.0-OpenSSH_8.2",
                    },
                    covers_tactics=["Lateral Movement"],
                )
            ]
        ),
        MockTemplateRuntime(runtime_repository),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.52"))

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="admin-jumpbox",
                    reason="unlock jumpbox",
                )
            ],
        )
    )

    assert response.binding.unlocked_assets == ["admin-jumpbox"]
    assert len(response.runtime_events) == 1
    runtime_event = response.runtime_events[0]
    assert runtime_event.asset_id == "admin-jumpbox"
    assert runtime_event.template_family == "ssh-honeypot"
    assert runtime_event.protocols == ["ssh"]
    assert runtime_event.ports == [22]
    assert runtime_event.settings["hostname"] == "admin-jumpbox-01"
    assert runtime_event.settings["ssh_banner"] == "SSH-2.0-OpenSSH_8.2"

    assert len(response.monitoring_events) == 1
    monitoring_event = response.monitoring_events[0]
    assert monitoring_event.falco_rule == "Honeynet asset template started"
    assert monitoring_event.tags == ["honeynet_asset_runtime"]
    assert monitoring_event.output_fields["asset_id"] == "admin-jumpbox"

    stored_records = tuple(runtime_repository.list_by_binding(binding.binding_id))
    assert len(stored_records) == 1
    assert stored_records[0].asset_id == "admin-jumpbox"


def test_recycle_then_resolve_keeps_unlocked_assets() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
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


def test_recycle_stops_runtime_records_for_binding() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
        InMemoryAssetRepository(
            [
                AssetDefinition(
                    asset_id="internal-portal",
                    asset_name="Internal Portal",
                    exposure_type="internal",
                    interaction_level="medium",
                    template_family="web-honeypot",
                    protocols=["http"],
                    ports=[80],
                    default_settings={"route_path": "/portal"},
                    covers_tactics=["Discovery"],
                )
            ]
        ),
        MockTemplateRuntime(runtime_repository),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.53"))
    orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="internal-portal",
                    reason="start portal",
                )
            ],
        )
    )

    recycled = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.recycle,
                    binding_id=binding.binding_id,
                    reason="cleanup",
                )
            ],
        )
    )

    assert recycled.runtime_events[0].asset_id == "internal-portal"
    assert recycled.runtime_events[0].status == "stopped"
    assert recycled.monitoring_events[0].falco_rule == "Honeynet asset template stopped"


def test_resolve_host_port_falls_back_when_requested_port_is_busy() -> None:
    busy_port = 18080

    original_find = template_runtime_module._find_free_port
    original_port_is_free = template_runtime_module._port_is_free
    template_runtime_module._find_free_port = lambda: 28080
    template_runtime_module._port_is_free = lambda port: False
    try:
        resolved = _resolve_host_port(busy_port)
    finally:
        template_runtime_module._find_free_port = original_find
        template_runtime_module._port_is_free = original_port_is_free

    assert resolved == 28080


def test_docker_template_runtime_renders_web_root_from_external_template(tmp_path) -> None:
    runtime = DockerTemplateRuntime(
        InMemoryTemplateRuntimeRepository(),
        tmp_path / "generated",
    )
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        description="Fake employee portal",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={"http_title": "Employee Self Service", "route_path": "/portal"},
        covers_tactics=["Discovery"],
    )

    web_root = runtime._prepare_web_root("binding-1", asset)
    html = (web_root / "index.html").read_text(encoding="utf-8")

    assert "Employee Self Service" in html
    assert "Fake employee portal" in html
    assert "/portal" in html
