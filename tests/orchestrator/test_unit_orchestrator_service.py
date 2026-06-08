from __future__ import annotations

import json
from collections.abc import Callable

import services.orchestrator.runtime_routes as runtime_routes_module
import services.orchestrator.template_runtime as template_runtime_module
import pytest

from libs.contracts.models import (
    ActionType,
    AssetDefinition,
    ControllerAction,
    OrchestratorApplyRequest,
    OrchestratorPrewarmRequest,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from tests.support.inmemory_repositories import InMemoryBindingRepository
from tests.support.inmemory_repositories import InMemoryAssetRepository
from services.gateway.domain import GatewayService
from services.gateway.domain import GatewayStateNotFoundError
from tests.support.inmemory_repositories import InMemoryGatewayRouteRepository
from tests.support.inmemory_repositories import InMemoryTemplateRuntimeRepository
from services.orchestrator.domain import OrchestratorService
from services.orchestrator.template_runtime import (
    ComposeTemplateRuntime,
    DockerTemplateRuntime,
    MockTemplateRuntime,
    HybridTemplateRuntime,
)
from services.orchestrator.runtime_routes import _resolve_host_port


pytestmark = pytest.mark.unit


def _missing_then_up_status() -> Callable[[str], str]:
    calls = {"count": 0}

    def fake_container_status(name: str) -> str:
        calls["count"] += 1
        if calls["count"] == 1:
            return "missing"
        return "Up 3 seconds"

    return fake_container_status


def test_wait_for_container_removal_polls_until_name_is_released(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statuses = iter(["Removal In Progress", "Removal In Progress", "missing"])
    monkeypatch.setattr(template_runtime_module, "_container_status", lambda name: next(statuses))
    monkeypatch.setattr(template_runtime_module.time, "sleep", lambda seconds: None)

    template_runtime_module._wait_for_container_removal("honeynet-test-ops-db")


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
        f"binding {binding.binding_id} exposes git-internal",
        f"binding {binding.binding_id} routes git-internal",
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


def test_apply_configure_records_configuration_and_unlocks_upgrade_target(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))
    html_root = tmp_path / "deploy" / "internal-assets" / "malware-sink" / "html"
    html_root.mkdir(parents=True)
    (html_root / "index.html").write_text("<html><body>base</body></html>", encoding="utf-8")
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
        InMemoryAssetRepository(
            [
                AssetDefinition(
                    asset_id="malware-sink",
                    asset_name="Malware Sink",
                    exposure_type="internal",
                    interaction_level="medium",
                    template_family="web-honeypot",
                    protocols=["http"],
                    ports=[80],
                    default_settings={
                        "runtime": {
                            "backend": "mock",
                            "volumes": [
                                "{host_project_root}/deploy/internal-assets/malware-sink/html:/usr/share/nginx/html:ro"
                            ],
                        }
                    },
                    covers_tactics=["Command and Control"],
                ),
                AssetDefinition(
                    asset_id="dionaea-capture",
                    asset_name="Dionaea Capture",
                    exposure_type="internal",
                    interaction_level="high",
                    template_family="malware-capture-service",
                    protocols=["http", "smb"],
                    ports=[80, 445],
                    default_settings={"runtime": {"backend": "mock"}},
                    covers_tactics=["Command and Control", "Execution"],
                ),
            ]
        ),
        MockTemplateRuntime(runtime_repository),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.54"))
    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="malware-sink",
                    reason="start base malware sink",
                )
            ],
        )
    )

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.configure,
                    binding_id=binding.binding_id,
                    asset_id="malware-sink",
                    configuration_id="malware-dionaea-same-port-upgrade",
                    target_asset_id="dionaea-capture",
                    configuration={
                        "kind": "target-runtime-same-port",
                        "materialized_artifacts": [
                            {
                                "type": "route_note",
                                "text": "Future malware-sink traffic is handled by dionaea-capture.",
                            }
                        ],
                    },
                    reason="upgrade malware capture backend",
                )
            ],
        )
    )

    assert response.binding.unlocked_assets == ["malware-sink", "dionaea-capture"]
    assert response.binding.revealed_configurations == {
        "malware-sink": ["malware-dionaea-same-port-upgrade"]
    }
    assert response.route_updates == [
        f"binding {binding.binding_id} configures malware-sink:malware-dionaea-same-port-upgrade",
        f"binding {binding.binding_id} exposes dionaea-capture",
    ]
    stored_records = tuple(runtime_repository.list_by_binding(binding.binding_id))
    source_record = next(record for record in stored_records if record.asset_id == "malware-sink")
    assert "malware-dionaea-same-port-upgrade" in source_record.settings["active_configurations"]
    artifact = source_record.settings["configuration_artifacts"][
        "malware-dionaea-same-port-upgrade"
    ]
    assert artifact["url_path"] == "/_reveals/malware-dionaea-same-port-upgrade.json"
    artifact_path = html_root / "_reveals" / "malware-dionaea-same-port-upgrade.json"
    assert artifact_path.exists()
    artifact_payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact_payload["asset_id"] == "malware-sink"
    assert artifact_payload["configuration_id"] == "malware-dionaea-same-port-upgrade"
    assert artifact_payload["route_notes"] == [
        "Future malware-sink traffic is handled by dionaea-capture."
    ]
    assert (html_root / "_reveals" / "index.html").exists()
    updated_index = (html_root / "index.html").read_text(encoding="utf-8")
    assert 'data-config-reveal="malware-dionaea-same-port-upgrade"' in updated_index
    assert "/_reveals/malware-dionaea-same-port-upgrade.json" in updated_index
    assert any(record.asset_id == "dionaea-capture" for record in stored_records)


def test_apply_configure_materializes_catalog_files_and_links(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))
    html_root = tmp_path / "deploy" / "internal-assets" / "internal-portal" / "html"
    html_root.mkdir(parents=True)
    (html_root / "index.html").write_text("<html><body>portal</body></html>", encoding="utf-8")
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
                    default_settings={
                        "runtime": {
                            "backend": "mock",
                            "volumes": [
                                "{host_project_root}/deploy/internal-assets/internal-portal/html:/usr/share/nginx/html:ro"
                            ],
                        }
                    },
                    covers_tactics=["Discovery"],
                )
            ]
        ),
        MockTemplateRuntime(runtime_repository),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.56"))
    response = orchestrator.apply(
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

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.configure,
                    binding_id=binding.binding_id,
                    asset_id="internal-portal",
                    configuration_id="portal-admin-console-link",
                    configuration={
                        "kind": "content",
                        "materialized_artifacts": [
                            {
                                "type": "file",
                                "path": "runbooks/admin-console-access.md",
                                "content": "Admin console: http://127.0.0.1:18081/",
                            },
                            {
                                "type": "index_link",
                                "href": "/runbooks/admin-console-access.md",
                                "label": "Admin console access note",
                                "description": "Operations link exposed on the active portal path.",
                            },
                        ],
                    },
                    reason="add active-path admin console clue",
                )
            ],
        )
    )

    clue_path = html_root / "runbooks" / "admin-console-access.md"
    assert clue_path.read_text(encoding="utf-8") == "Admin console: http://127.0.0.1:18081/"
    updated_index = (html_root / "index.html").read_text(encoding="utf-8")
    assert 'href="/runbooks/admin-console-access.md"' in updated_index
    assert "Admin console access note" in updated_index
    stored_record = next(iter(runtime_repository.list_by_binding(binding.binding_id)))
    artifact = stored_record.settings["configuration_artifacts"]["portal-admin-console-link"]
    assert artifact["materialized_artifacts"] == [
        {
            "type": "file",
            "path": str(clue_path),
            "url_path": "/runbooks/admin-console-access.md",
        },
        {
            "type": "index_link",
            "href": "/runbooks/admin-console-access.md",
            "label": "Admin console access note",
        },
    ]


def test_apply_configure_can_swap_same_asset_target_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    asset = AssetDefinition(
        asset_id="redis-cache",
        asset_name="Redis Cache",
        exposure_type="internal",
        interaction_level="medium",
        template_family="cache-service",
        protocols=["redis"],
        ports=[6379],
        default_settings={
            "runtime": {
                "backend": "mock",
                "image": "thinkst/opencanary",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 16379,
                        "container_port": 6379,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
        InMemoryAssetRepository([asset]),
        MockTemplateRuntime(runtime_repository),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.57"))
    orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="redis-cache",
                    reason="start base redis canary",
                )
            ],
        )
    )

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.configure,
                    binding_id=binding.binding_id,
                    asset_id="redis-cache",
                    configuration_id="redis-seeded-keyspace-backend",
                    target_asset_id="redis-cache",
                    configuration={
                        "kind": "same-port-target-runtime",
                        "target_asset_id": "redis-cache",
                        "target_runtime": {
                            "backend": "docker",
                            "image": "redis:7-alpine",
                            "port_mappings": [
                                {
                                    "host": "127.0.0.1",
                                    "requested_host_port": 16379,
                                    "container_port": 6379,
                                }
                            ],
                        },
                        "materialized_artifacts": [
                            {
                                "type": "route_note",
                                "text": "Redis reconnects now reach a seeded keyspace backend.",
                            }
                        ],
                    },
                    reason="swap redis backend",
                )
            ],
        )
    )

    assert response.route_updates == [
        f"binding {binding.binding_id} configures redis-cache:redis-seeded-keyspace-backend",
        f"binding {binding.binding_id} routes redis-cache",
    ]
    records = tuple(runtime_repository.list_by_binding(binding.binding_id))
    running_record = next(record for record in records if record.status == "running")
    assert running_record.asset_id == "redis-cache"
    assert running_record.settings["runtime"]["image"] == "redis:7-alpine"
    assert running_record.settings["configured_runtime"] is True
    assert "redis-seeded-keyspace-backend" in running_record.settings["active_configurations"]


def test_prewarm_starts_catalog_warm_assets_without_gateway_exposure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    docker_runtime = DockerTemplateRuntime(runtime_repository)
    mock_runtime = MockTemplateRuntime(runtime_repository)
    asset = AssetDefinition(
        asset_id="web-admin-console",
        asset_name="Web Admin Console",
        exposure_type="internal",
        interaction_level="medium",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "warm_standby": True,
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18081,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
        dependencies=["internal-portal"],
    )
    orchestrator = OrchestratorService(
        binding_service,
        gateway_service,
        InMemoryAssetRepository([asset]),
        HybridTemplateRuntime(docker_runtime, mock_runtime),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.55"))

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(
        template_runtime_module.subprocess,
        "run",
        lambda args, **kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": "container-id", "stderr": ""},
        )(),
    )
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)

    response = orchestrator.prewarm(
        OrchestratorPrewarmRequest(binding_id=binding.binding_id)
    )

    assert response.warmed_asset_ids == ["web-admin-console"]
    assert response.runtime_events[0].settings["warm_standby_hidden"] is True
    with pytest.raises(GatewayStateNotFoundError):
        gateway_service.get_state(binding.binding_id)
    assert orchestrator._accessible_asset_ids(binding.binding_id, binding) == []


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

    original_find = runtime_routes_module._find_free_port
    original_port_is_free = runtime_routes_module._port_is_free
    runtime_routes_module._find_free_port = lambda: 28080
    runtime_routes_module._port_is_free = lambda port: False
    try:
        resolved = _resolve_host_port(busy_port)
    finally:
        runtime_routes_module._find_free_port = original_find
        runtime_routes_module._port_is_free = original_port_is_free

    assert resolved == 28080


def test_docker_template_runtime_starts_catalog_driven_cowrie_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_args: list[str] = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = "container-id"
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)

    repository = InMemoryTemplateRuntimeRepository()
    runtime = DockerTemplateRuntime(repository)
    asset = AssetDefinition(
        asset_id="admin-jumpbox",
        asset_name="Admin Jumpbox",
        exposure_type="internal",
        interaction_level="high",
        template_family="ssh-honeypot",
        protocols=["ssh"],
        ports=[22],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "ghcr.io/telekom-security/cowrie:24.04.1",
                "entrypoint": "/bin/sh",
                "command": [
                    "-lc",
                    "mkdir -p /tmp/cowrie /tmp/cowrie/data etc && exec cowrie",
                ],
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 10222,
                        "container_port": 22,
                    }
                ],
            }
        },
        covers_tactics=["Lateral Movement"],
    )

    record = runtime.start_asset("binding-cowrie", asset)

    assert captured_args[:4] == ["docker", "run", "-d", "--name"]
    assert "honeynet.mvp=true" in captured_args
    assert "honeynet.asset_id=admin-jumpbox" in captured_args
    assert "-p" not in captured_args
    assert "--network" in captured_args
    assert "--entrypoint" in captured_args
    assert "/bin/sh" in captured_args
    assert "ghcr.io/telekom-security/cowrie:24.04.1" in captured_args
    assert "mkdir -p /tmp/cowrie /tmp/cowrie/data etc && exec cowrie" in captured_args
    assert record.settings["runtime_backend"] == "docker"
    assert record.settings["asset_gateway_managed"] is True
    assert record.settings["host_port"] == 10222
    assert record.settings["container_port"] == 22
    assert record.settings["backend_port"] == 22


def test_docker_template_runtime_uses_stable_internal_portal_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_args: list[str] = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = "container-id"
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18080,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    record = runtime.start_asset("binding-wordpot", asset)

    assert "nginx:alpine" in captured_args
    assert "--read-only" not in captured_args
    assert "-v" not in captured_args
    assert "-p" not in captured_args
    assert "--network" in captured_args
    assert record.settings["runtime_backend"] == "docker"
    assert record.settings["image"] == "nginx:alpine"
    assert record.settings["asset_gateway_managed"] is True
    assert record.settings["public_port"] == 18080


def test_docker_template_runtime_writes_asset_gateway_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured_args: list[str] = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = (
                json.dumps(
                    [
                        {
                            "NetworkSettings": {
                                "Networks": {
                                    "honeynet_net_internal": {
                                        "IPAddress": "172.25.0.5",
                                    }
                                }
                            }
                        }
                    ]
                )
                if args[:2] == ["docker", "inspect"]
                else "container-id"
            )
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    monkeypatch.setenv(
        "HONEYPOT_ASSET_GATEWAY_ROUTES_PATH",
        str(tmp_path / "asset_gateway_routes.json"),
    )

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18080,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    record = runtime.start_asset(
        "binding-route",
        asset,
        attacker_key="198.51.100.77",
    )
    routes = json.loads((tmp_path / "asset_gateway_routes.json").read_text())

    assert "-p" not in captured_args
    assert routes["routes"][0]["attacker_key"] == "198.51.100.77"
    assert routes["routes"][0]["binding_id"] == "binding-route"
    assert routes["routes"][0]["asset_id"] == "internal-portal"
    assert routes["routes"][0]["public_port"] == 18080
    assert routes["routes"][0]["backend_host"] == record.settings["backend_host"]
    assert routes["routes"][0]["backend_port"] == 80
    assert routes["routes"][0]["backend_ip"] == "172.25.0.5"


def test_docker_template_runtime_attaches_route_to_warm_standby_backend(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        command = list(args)
        commands.append(command)

        class Result:
            returncode = 0
            stdout = (
                json.dumps(
                    [
                        {
                            "NetworkSettings": {
                                "Networks": {
                                    "honeynet_net_internal": {
                                        "IPAddress": "172.25.0.9",
                                    }
                                }
                            }
                        }
                    ]
                )
                if command[:2] == ["docker", "inspect"]
                else "container-id"
            )
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    monkeypatch.setenv(
        "HONEYPOT_ASSET_GATEWAY_ROUTES_PATH",
        str(tmp_path / "asset_gateway_routes.json"),
    )

    repository = InMemoryTemplateRuntimeRepository()
    runtime = DockerTemplateRuntime(repository)
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "network": "honeynet_net_internal",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18080,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    warm_record = runtime.start_asset("binding-warm", asset, warm_standby=True)
    assert warm_record.settings["warm_standby_hidden"] is True
    assert not (tmp_path / "asset_gateway_routes.json").exists()

    revealed_record = runtime.start_asset(
        "binding-warm",
        asset,
        attacker_key="198.51.100.90",
    )
    routes = json.loads((tmp_path / "asset_gateway_routes.json").read_text())

    docker_run_commands = [command for command in commands if command[:2] == ["docker", "run"]]
    assert len(docker_run_commands) == 1
    assert revealed_record.settings["warm_standby_hidden"] is False
    assert routes["routes"][0]["attacker_key"] == "198.51.100.90"
    assert routes["routes"][0]["asset_id"] == "internal-portal"
    assert routes["routes"][0]["public_port"] == 18080
    assert routes["routes"][0]["backend_ip"] == "172.25.0.9"


def test_docker_template_runtime_does_not_gateway_manage_external_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_args: list[str] = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = "container-id"
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="web-entrypoint",
        asset_name="Web Entrypoint",
        exposure_type="public",
        interaction_level="low",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 8083,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    record = runtime.start_asset("binding-entrypoint", asset)

    assert "-p" in captured_args
    assert "127.0.0.1:8083:80" in captured_args
    assert "asset_gateway_managed" not in record.settings


def test_docker_template_runtime_starts_internal_opencanary_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_args: list[str] = []

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = "container-id"
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", "/srv/honeypot")

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="git-internal",
        asset_name="Internal Git",
        exposure_type="internal",
        interaction_level="medium",
        template_family="developer-service-honeypot",
        protocols=["git"],
        ports=[9418],
        source_refs=["opencanary:git"],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "thinkst/opencanary",
                "network": "{project_name}_net_internal",
                "memory_limit": "256m",
                "volumes": [
                    "{host_project_root}/deploy/opencanary/internal/git.conf:/root/.opencanary.conf:ro",
                    "{host_project_root}/deploy/opencanary/var:/var/tmp",
                ],
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 19418,
                        "container_port": 9418,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
        dependencies=["internal-portal"],
    )

    record = runtime.start_asset("binding-git", asset)

    assert "--network" in captured_args
    assert "honeynet_net_internal" in captured_args
    assert "--memory" in captured_args
    assert "256m" in captured_args
    assert "/srv/honeypot/deploy/opencanary/internal/git.conf:/root/.opencanary.conf:ro" in captured_args
    assert "/srv/honeypot/deploy/opencanary/var:/var/tmp" in captured_args
    assert "-p" not in captured_args
    assert "thinkst/opencanary" in captured_args
    assert record.settings["runtime_backend"] == "docker"
    assert record.settings["network"] == "honeynet_net_internal"
    assert record.settings["memory_limit"] == "256m"
    assert record.settings["public_port"] == 19418
    assert record.settings["backend_port"] == 9418


def test_docker_template_runtime_mounts_static_assets_from_binding_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    captured_args: list[str] = []
    source_html = tmp_path / "deploy" / "internal-assets" / "internal-portal" / "html"
    source_html.mkdir(parents=True)
    (source_html / "index.html").write_text("<h1>base portal</h1>", encoding="utf-8")

    def fake_run(args, **kwargs):
        captured_args.extend(args)

        class Result:
            returncode = 0
            stdout = "container-id"
            stderr = ""

        return Result()

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", _missing_then_up_status())
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        template_family="internal-portal",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "volumes": [
                    "{host_project_root}/deploy/internal-assets/internal-portal/html:/usr/share/nginx/html:ro"
                ],
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18080,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    record = runtime.start_asset("binding-static-copy", asset)

    copied_html = (
        tmp_path
        / "data"
        / "runtime"
        / "configurable_assets"
        / "binding-"
        / "internal-portal"
        / "html"
    )
    assert (copied_html / "index.html").read_text(encoding="utf-8") == "<h1>base portal</h1>"
    assert (
        f"{copied_html}:/usr/share/nginx/html:ro" in captured_args
    )
    assert record.settings["volumes"] == [f"{copied_html}:/usr/share/nginx/html:ro"]


def test_compose_template_runtime_starts_catalog_driven_compose_asset(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []
    compose_file = tmp_path / "vendor" / "optional-web-lab" / "docker-compose.yml"
    compose_file.parent.mkdir(parents=True)
    compose_file.write_text("version: '2'\nservices:\n  app:\n    image: example/web-lab\n", encoding="utf-8")

    def fake_run(args, **kwargs):
        command = list(args)
        commands.append(command)

        class Result:
            def __init__(self, stdout: str = "", returncode: int = 0) -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = ""

        if command[:2] == ["docker", "run"] and "up" in command:
            return Result(stdout="started")
        if command[:2] == ["docker", "run"] and "ps" in command:
            return Result(stdout="container-1\n")
        if command[:3] == ["docker", "network", "inspect"]:
            return Result(stdout="{}")
        if command[:2] == ["docker", "inspect"]:
            return Result(stdout="{}")
        if command[:3] == ["docker", "network", "connect"]:
            return Result(stdout="")
        if command[:3] == ["docker", "ps", "-a"]:
            return Result(stdout="honeynet-binding-compose-web-lab-1\tUp 3 seconds\n")
        raise AssertionError(f"unexpected subprocess call: {command}")

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", str(tmp_path))

    runtime = ComposeTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="compose-web-lab",
        asset_name="Optional Compose Web Lab",
        exposure_type="internal",
        interaction_level="high",
        template_family="compose-web-lab",
        protocols=["http"],
        ports=[8080],
        source_refs=["optional:compose-web-lab"],
        default_settings={
            "runtime": {
                "backend": "compose",
                "compose_file": "vendor/optional-web-lab/docker-compose.yml",
                "project_name": "{project_name}-{binding_id_short}-{asset_id}",
                "runner": "docker_image",
                "compose_image": "docker/compose:1.29.2",
                "internal_network": "{project_name}_net_internal",
                "source": "optional-web-lab",
            }
        },
        covers_tactics=["Initial Access", "Execution", "Discovery"],
        dependencies=["internal-portal"],
    )

    record = runtime.start_asset("binding-compose", asset)

    assert record.settings["runtime_backend"] == "compose"
    assert record.settings["compose_project"] == "honeynet-binding--compose-web-lab"
    assert record.settings["internal_network"] == "honeynet_net_internal"
    assert record.settings["container_ids"] == ["container-1"]
    assert any("docker/compose:1.29.2" in command for command in commands)
    assert any(command[:3] == ["docker", "network", "connect"] for command in commands)


def test_docker_template_runtime_raises_when_container_exits_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))

        class Result:
            def __init__(self, stdout: str = "", returncode: int = 0) -> None:
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = ""

        if args[:2] == ["docker", "run"]:
            return Result(stdout="container-id")
        if args[:3] == ["docker", "ps", "-a"]:
            return Result(stdout="")
        if args[:3] == ["docker", "rm", "-f"]:
            return Result(stdout="")
        raise AssertionError(f"unexpected subprocess call: {args}")

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.time, "sleep", lambda _: None)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="redis-cache",
        asset_name="Redis Cache",
        exposure_type="internal",
        interaction_level="medium",
        template_family="redis-honeypot",
        protocols=["redis"],
        ports=[6379],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "dtagdevsec/redishoneypot:24.04",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 6379,
                        "container_port": 6379,
                    }
                ],
                "healthcheck": {
                    "type": "tcp",
                    "host": "127.0.0.1",
                    "port_setting": "host_port",
                },
            }
        },
        covers_tactics=["Discovery"],
    )

    with pytest.raises(RuntimeError, match="failed startup verification"):
        runtime.start_asset("binding-redis", asset)

    assert any(command[:3] == ["docker", "rm", "-f"] for command in commands)


def test_docker_template_runtime_reuses_running_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def fake_run(args, **kwargs):
        commands.append(list(args))
        raise AssertionError(f"unexpected subprocess call: {args}")

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module, "_container_status", lambda name: "Up 2 seconds")
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    monkeypatch.setattr(template_runtime_module, "_container_network_ip", lambda name, network: "172.25.0.9")
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)

    runtime = DockerTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="internal-portal",
        asset_name="Internal Portal",
        exposure_type="internal",
        interaction_level="medium",
        template_family="web-honeypot",
        protocols=["http"],
        ports=[80],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "nginx:alpine",
                "port_mappings": [
                    {
                        "host": "127.0.0.1",
                        "requested_host_port": 18080,
                        "container_port": 80,
                    }
                ],
            }
        },
        covers_tactics=["Discovery"],
    )

    record = runtime.start_asset("binding-portal", asset)

    assert record.status == "running"
    assert record.settings["container_name"] == "honeynet-binding--internal-portal"
    assert record.settings["backend_ip"] == "172.25.0.9"
    assert commands == []


def test_orchestrator_gateway_excludes_exited_docker_assets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    runtime_repository = InMemoryTemplateRuntimeRepository()
    docker_runtime = DockerTemplateRuntime(runtime_repository)
    mock_runtime = MockTemplateRuntime(runtime_repository)
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
                    default_settings={
                        "runtime": {
                            "backend": "docker",
                            "image": "nginx:alpine",
                            "port_mappings": [
                                {
                                    "host": "127.0.0.1",
                                    "requested_host_port": 18080,
                                    "container_port": 80,
                                }
                            ],
                        }
                    },
                    covers_tactics=["Discovery"],
                )
            ]
        ),
        HybridTemplateRuntime(docker_runtime, mock_runtime),
    )
    binding = binding_service.resolve(ResolveBindingRequest(attacker_key="198.51.100.88"))

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(runtime_routes_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(
        template_runtime_module.subprocess,
        "run",
        lambda args, **kwargs: type(
            "Result",
            (),
            {"returncode": 0, "stdout": "container-id", "stderr": ""},
        )(),
    )
    monkeypatch.setattr(template_runtime_module, "_healthcheck_ready", lambda runtime, settings: True)
    status_calls = {"count": 0}

    def fake_container_status(name: str) -> str:
        status_calls["count"] += 1
        if status_calls["count"] == 1:
            return "Up 2 seconds"
        return "Exited (1) 1 second ago"

    monkeypatch.setattr(template_runtime_module, "_container_status", fake_container_status)

    response = orchestrator.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.unlock,
                    binding_id=binding.binding_id,
                    asset_id="internal-portal",
                    reason="unlock portal",
                )
            ],
        )
    )

    assert response.binding.unlocked_assets == ["internal-portal"]
    gateway_state = gateway_service.get_state(binding.binding_id)
    assert gateway_state.exposed_assets == []
    assert gateway_state.failed_assets == ["internal-portal"]


def test_hybrid_runtime_records_failed_asset_when_docker_start_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_repository = InMemoryTemplateRuntimeRepository()
    runtime = HybridTemplateRuntime(
        DockerTemplateRuntime(runtime_repository),
        MockTemplateRuntime(runtime_repository),
    )
    asset = AssetDefinition(
        asset_id="redis-cache",
        asset_name="Redis Cache",
        exposure_type="internal",
        interaction_level="medium",
        template_family="redis-honeypot",
        protocols=["redis"],
        ports=[6379],
        default_settings={
            "runtime": {
                "backend": "docker",
                "image": "dtagdevsec/redishoneypot:24.04",
            }
        },
        covers_tactics=["Discovery"],
    )

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(
        template_runtime_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("docker start failed")),
    )

    record = runtime.start_asset("binding-failed", asset)

    assert record.status == "failed"
    assert record.settings["runtime_backend"] == "docker"
    assert isinstance(record.settings["runtime_failure"], str)
    assert record.settings["runtime_failure"]
    assert runtime.list_accessible_asset_ids("binding-failed") == []
    assert runtime.list_failed_asset_ids("binding-failed") == ["redis-cache"]
