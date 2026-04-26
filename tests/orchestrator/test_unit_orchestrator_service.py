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
    ComposeTemplateRuntime,
    DockerTemplateRuntime,
    _resolve_host_port,
    InMemoryTemplateRuntimeRepository,
    MockTemplateRuntime,
    HybridTemplateRuntime,
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
    monkeypatch.setattr(template_runtime_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", lambda name: "Up 3 seconds")
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
                        "requested_host_port": 2222,
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
    assert "-p" in captured_args
    assert "127.0.0.1:2222:22" in captured_args
    assert "--entrypoint" in captured_args
    assert "/bin/sh" in captured_args
    assert "ghcr.io/telekom-security/cowrie:24.04.1" in captured_args
    assert "mkdir -p /tmp/cowrie /tmp/cowrie/data etc && exec cowrie" in captured_args
    assert record.settings["runtime_backend"] == "docker"
    assert record.settings["host_port"] == 2222
    assert record.settings["container_port"] == 22


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
    monkeypatch.setattr(template_runtime_module, "_port_is_free", lambda port: True)
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setattr(template_runtime_module, "_container_status", lambda name: "Up 3 seconds")
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
    assert "127.0.0.1:18080:80" in captured_args
    assert record.settings["runtime_backend"] == "docker"
    assert record.settings["image"] == "nginx:alpine"


def test_compose_template_runtime_starts_catalog_driven_vulhub_asset(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    commands: list[list[str]] = []
    compose_file = tmp_path / "vendor" / "vulhub" / "log4j" / "CVE-2021-44228" / "docker-compose.yml"
    compose_file.parent.mkdir(parents=True)
    compose_file.write_text("version: '2'\nservices:\n  app:\n    image: vulhub/log4j\n", encoding="utf-8")

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
            return Result(stdout="honeynet-binding-log4shell-app-1\tUp 3 seconds\n")
        raise AssertionError(f"unexpected subprocess call: {command}")

    monkeypatch.setattr(template_runtime_module.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(template_runtime_module.subprocess, "run", fake_run)
    monkeypatch.setenv("HONEYPOT_PROJECT_NAME", "honeynet")
    monkeypatch.setenv("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(tmp_path))
    monkeypatch.setenv("HONEYPOT_HOST_PROJECT_ROOT", str(tmp_path))

    runtime = ComposeTemplateRuntime(InMemoryTemplateRuntimeRepository())
    asset = AssetDefinition(
        asset_id="log4shell-app",
        asset_name="Legacy Java App",
        exposure_type="internal",
        interaction_level="high",
        template_family="vulnerable-webapp-honeypot",
        protocols=["http"],
        ports=[8080],
        source_refs=["vulhub:log4j/CVE-2021-44228"],
        default_settings={
            "runtime": {
                "backend": "compose",
                "compose_file": "vendor/vulhub/log4j/CVE-2021-44228/docker-compose.yml",
                "project_name": "{project_name}-{binding_id_short}-{asset_id}",
                "runner": "docker_image",
                "compose_image": "docker/compose:1.29.2",
                "internal_network": "{project_name}_net_internal",
                "source": "vulhub/log4j/CVE-2021-44228",
            }
        },
        covers_tactics=["Initial Access", "Execution", "Discovery"],
        dependencies=["internal-portal"],
    )

    record = runtime.start_asset("binding-compose", asset)

    assert record.settings["runtime_backend"] == "compose"
    assert record.settings["compose_project"] == "honeynet-binding--log4shell-app"
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
    monkeypatch.setattr(template_runtime_module, "_port_is_free", lambda port: True)
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
    monkeypatch.setattr(template_runtime_module, "_port_is_free", lambda port: True)
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
