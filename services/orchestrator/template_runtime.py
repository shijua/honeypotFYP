"""Template runtime adapters for enabled decoy assets.

This module separates "controller chose an asset" from "something concrete was
started for that asset". The current MVP supports:

- a mock runtime that only records the start plan
- a Docker-backed runtime for a small safe subset of templates
- a Compose-backed runtime for high-interaction vulnerable asset scenarios

Docker runtimes may also declare `runtime.sidecar_forwarders`. These are small
companion containers, usually Python forwarders, that mount the backend log
directory and post telemetry into the control-plane adapters. Keeping log
forwarding in sidecars lets backend honeypot images stay unmodified and keeps
control-network access out of attacker-facing containers.

Both runtimes emit Falco-style lifecycle events so the rest of the prototype
can observe template starts/stops before real Falco container telemetry is
wired in.
"""

from __future__ import annotations

from collections.abc import Iterable
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from typing import Protocol
from uuid import uuid4

from libs.common.clock import utcnow
from libs.common.iterables import dedupe_preserve
from libs.common.json_store import JsonFileStore
from libs.contracts.models import AssetDefinition, AssetRuntimeRecord, FalcoEvent
from services.orchestrator.runtime_routes import asset_gateway_managed as is_asset_gateway_managed
from services.orchestrator.runtime_routes import resolve_port_mappings
from services.orchestrator.runtime_routes import upsert_asset_gateway_routes


class TemplateRuntimeRepository(Protocol):
    """Storage contract for asset runtime records."""

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        """Insert or update one asset runtime record."""
        ...

    def list_by_binding(self, binding_id: str) -> Iterable[AssetRuntimeRecord]:
        """Return runtime records associated with one binding."""
        ...


class FileTemplateRuntimeRepository:
    """File-backed runtime store for default local orchestration."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"records": []})

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        self._store.upsert_list_item(
            "records",
            "runtime_id",
            record.runtime_id,
            record.model_dump(mode="json"),
        )
        return record

    def list_by_binding(self, binding_id: str) -> Iterable[AssetRuntimeRecord]:
        payload = self._store.read()
        return tuple(
            AssetRuntimeRecord.model_validate(item)
            for item in payload.get("records", [])
            if item.get("binding_id") == binding_id
        )


class MockTemplateRuntime:
    """Plan and record asset starts without creating real infrastructure.

    Use this when an asset has no safe real runtime yet, or when local Docker is
    unavailable. It keeps the orchestrator flow working and still exposes a
    runtime record plus Falco-style lifecycle event.
    """

    def __init__(self, repository: TemplateRuntimeRepository) -> None:
        self._repository = repository

    def start_asset(
        self,
        binding_id: str,
        asset: AssetDefinition,
        attacker_key: str | None = None,
    ) -> AssetRuntimeRecord:
        """Record that an asset is running with its catalog default settings."""
        existing = _existing_running_record(self._repository, binding_id, asset.asset_id)
        if existing is not None:
            return existing

        record = _runtime_record_from_asset(binding_id, asset)
        return self._repository.upsert(record)

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Convert a mock runtime record into a Falco-style lifecycle event."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Mark running records as stopped for one binding."""
        stopped: list[AssetRuntimeRecord] = []
        for record in self._repository.list_by_binding(binding_id):
            if record.status != "running":
                continue
            updated = record.model_copy(update={"status": "stopped"})
            self._repository.upsert(updated)
            stopped.append(updated)
        return stopped

    def upsert_record(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        """Persist an updated runtime record back into the mock repository."""
        return self._repository.upsert(record)

    def apply_configuration(
        self,
        binding_id: str,
        asset_id: str,
        configuration_id: str,
        configuration: dict[str, object],
    ) -> AssetRuntimeRecord | None:
        """Record an A.2 configuration reveal on an already-running asset.

        Example:
            git-internal + git-db-credential-clue updates runtime settings with
            active_configurations={"git-db-credential-clue": {...}}.
        """
        return _apply_configuration_to_record(
            self._repository,
            binding_id,
            asset_id,
            configuration_id,
            configuration,
        )

    def list_accessible_asset_ids(self, binding_id: str) -> list[str]:
        """Return currently reachable mock assets for one binding."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if (
                record.status == "running"
                and str(record.settings.get("runtime_backend", "mock")) != "docker"
            ):
                asset_ids.append(record.asset_id)
        return asset_ids

    def list_failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return failed mock/runtime placeholder assets for one binding."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if _runtime_record_is_failed(record):
                asset_ids.append(record.asset_id)
        return asset_ids


class DockerTemplateRuntime:
    """Start a small safe subset of templates as real Docker containers.

    Current scope:
    - catalog-driven Docker honeypots such as Cowrie, Wordpot, Redishoneypot

    The catalog owns image/port/command details. This adapter only translates
    that runtime spec into a safe local `docker run` call and records the
    resulting container metadata.
    """

    def __init__(
        self,
        repository: TemplateRuntimeRepository,
    ) -> None:
        self._repository = repository

    def supports(self, asset: AssetDefinition) -> bool:
        runtime = asset.default_settings.get("runtime", {})
        return isinstance(runtime, dict) and runtime.get("backend") == "docker"

    def start_asset(
        self,
        binding_id: str,
        asset: AssetDefinition,
        attacker_key: str | None = None,
    ) -> AssetRuntimeRecord:
        """Start one supported asset as a real Docker container."""
        existing = _existing_running_record(self._repository, binding_id, asset.asset_id)
        if existing is not None:
            return existing

        if shutil.which("docker") is None:
            raise RuntimeError("docker CLI is not available on this host")
        if not self.supports(asset):
            raise RuntimeError(f"asset {asset.asset_id} is not supported by DockerTemplateRuntime")

        runtime = dict(asset.default_settings.get("runtime", {}))
        image = runtime.get("image")
        if not isinstance(image, str) or not image:
            raise RuntimeError(f"asset {asset.asset_id} runtime is missing a Docker image")
        container_name = _container_name(binding_id, asset.asset_id)
        asset_gateway_managed = is_asset_gateway_managed(asset, runtime)

        docker_args, runtime_settings = self._docker_args_for_runtime(
            binding_id,
            asset,
            runtime,
            container_name,
            image,
            asset_gateway_managed=asset_gateway_managed,
        )
        existing_container_status = _container_status(container_name)
        if existing_container_status.startswith("Up"):
            self._verify_started_container(
                container_name=container_name,
                runtime=runtime,
                runtime_settings=runtime_settings,
            )
            runtime_settings["sidecar_containers"] = self._start_sidecar_forwarders(
                binding_id=binding_id,
                asset=asset,
                runtime=runtime,
                main_container_name=container_name,
                attacker_key=attacker_key,
            )
            return self._record_running_container(
                binding_id=binding_id,
                asset=asset,
                runtime_settings=runtime_settings,
                asset_gateway_managed=asset_gateway_managed,
                attacker_key=attacker_key,
                container_name=container_name,
            )
        if existing_container_status != "missing":
            self._cleanup_failed_container(container_name)

        try:
            subprocess.run(
                docker_args,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            self._cleanup_failed_container(container_name)
            raise RuntimeError(_docker_run_error_message(exc)) from exc

        self._verify_started_container(
            container_name=container_name,
            runtime=runtime,
            runtime_settings=runtime_settings,
        )
        runtime_settings["sidecar_containers"] = self._start_sidecar_forwarders(
            binding_id=binding_id,
            asset=asset,
            runtime=runtime,
            main_container_name=container_name,
            attacker_key=attacker_key,
        )
        return self._record_running_container(
            binding_id=binding_id,
            asset=asset,
            runtime_settings=runtime_settings,
            asset_gateway_managed=asset_gateway_managed,
            attacker_key=attacker_key,
            container_name=container_name,
        )

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Convert a Docker runtime record into a Falco-style lifecycle event."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop all running Docker-backed assets for one binding."""
        stopped: list[AssetRuntimeRecord] = []
        for record in self._repository.list_by_binding(binding_id):
            if record.status != "running":
                continue
            sidecar_containers = record.settings.get("sidecar_containers", [])
            if isinstance(sidecar_containers, list):
                for sidecar in sidecar_containers:
                    if isinstance(sidecar, str) and sidecar:
                        subprocess.run(
                            ["docker", "rm", "-f", sidecar],
                            check=False,
                            capture_output=True,
                            text=True,
                        )
            container_name = record.settings.get("container_name")
            if isinstance(container_name, str) and container_name:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            updated = record.model_copy(update={"status": "stopped"})
            self._repository.upsert(updated)
            stopped.append(updated)
        return stopped

    def list_accessible_asset_ids(self, binding_id: str) -> list[str]:
        """Return Docker assets whose containers are still Up right now."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if _runtime_record_is_accessible(record):
                asset_ids.append(record.asset_id)
        return asset_ids

    def list_failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return Docker assets whose runtime has failed or exited."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if _runtime_record_is_failed(record):
                asset_ids.append(record.asset_id)
        return asset_ids

    def _docker_args_for_runtime(
        self,
        binding_id: str,
        asset: AssetDefinition,
        runtime: dict[str, object],
        container_name: str,
        image: str,
        *,
        asset_gateway_managed: bool = False,
    ) -> tuple[list[str], dict[str, object]]:
        """Build a `docker run` command from the catalog runtime spec.

        The same path handles real T-Pot-style honeypot images. Asset-specific
        entrypoint, command, and port choices live in `catalog.json` so we do
        not maintain custom honeypot implementations in Python.
        """
        docker_args = [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "--label",
            "honeynet.mvp=true",
            "--label",
            f"honeynet.binding_id={binding_id}",
            "--label",
            f"honeynet.asset_id={asset.asset_id}",
        ]
        runtime_settings: dict[str, object] = {
            "runtime_backend": "docker",
            "container_name": container_name,
            "image": image,
        }
        format_context = _runtime_format_context(binding_id, asset.asset_id)

        network = runtime.get("network")
        if asset_gateway_managed and not isinstance(network, str):
            network = "{project_name}_net_internal"
        if isinstance(network, str) and network.strip():
            network_name = _format_runtime_string(network, format_context)
            docker_args.extend(["--network", network_name])
            runtime_settings["network"] = network_name

        memory_limit = runtime.get("memory_limit")
        if isinstance(memory_limit, str) and memory_limit.strip():
            docker_args.extend(["--memory", memory_limit.strip()])
            runtime_settings["memory_limit"] = memory_limit.strip()

        restart_policy = runtime.get("restart_policy")
        if isinstance(restart_policy, str) and restart_policy:
            docker_args.extend(["--restart", restart_policy])
            runtime_settings["restart_policy"] = restart_policy

        sysctls = runtime.get("sysctls", {})
        if isinstance(sysctls, dict):
            normalized_sysctls: dict[str, str] = {}
            for key, value in sysctls.items():
                sysctl_key = str(key).strip()
                if not sysctl_key:
                    continue
                sysctl_value = str(value)
                docker_args.extend(["--sysctl", f"{sysctl_key}={sysctl_value}"])
                normalized_sysctls[sysctl_key] = sysctl_value
            if normalized_sysctls:
                runtime_settings["sysctls"] = normalized_sysctls

        _append_runtime_list_option(docker_args, runtime_settings, runtime, "cap_add", "--cap-add")
        _append_runtime_list_option(docker_args, runtime_settings, runtime, "cap_drop", "--cap-drop")
        _append_runtime_list_option(docker_args, runtime_settings, runtime, "security_opt", "--security-opt")

        pids_limit = runtime.get("pids_limit")
        if isinstance(pids_limit, int) and pids_limit > 0:
            docker_args.extend(["--pids-limit", str(pids_limit)])
            runtime_settings["pids_limit"] = pids_limit

        _append_runtime_string_option(docker_args, runtime_settings, runtime, "user", "--user", format_context)
        _append_runtime_string_option(docker_args, runtime_settings, runtime, "working_dir", "-w", format_context)

        read_only = runtime.get("read_only")
        if isinstance(read_only, bool) and read_only:
            docker_args.append("--read-only")
            runtime_settings["read_only"] = True

        _append_runtime_list_option(docker_args, runtime_settings, runtime, "tmpfs", "--tmpfs")
        _prepare_runtime_volume_sources(runtime, format_context)
        _append_runtime_list_option(docker_args, runtime_settings, runtime, "volumes", "-v", format_context)

        port_records = resolve_port_mappings(
            runtime,
            asset.asset_id,
            asset_gateway_managed=asset_gateway_managed,
            backend_host=container_name,
        )
        for port_record in port_records:
            if not asset_gateway_managed:
                docker_args.extend(
                    [
                        "-p",
                        (
                            f"{port_record['host']}:{port_record['host_port']}:"
                            f"{port_record['container_port']}"
                        ),
                    ]
                )
        if port_records:
            first_port = port_records[0]
            runtime_settings.update(
                {
                    "host": first_port["host"],
                    "host_port": first_port["host_port"],
                    "container_port": first_port["container_port"],
                    "port_mappings": port_records,
                }
            )
            if asset_gateway_managed:
                runtime_settings.update(
                    {
                        "asset_gateway_managed": True,
                        "backend_host": container_name,
                        "backend_port": first_port["container_port"],
                        "public_port": first_port["host_port"],
                    }
                )

        _append_env_args(docker_args, runtime.get("env", {}), format_context)

        entrypoint = runtime.get("entrypoint")
        if isinstance(entrypoint, str) and entrypoint:
            docker_args.extend(
                ["--entrypoint", _format_runtime_string(entrypoint, format_context)]
            )

        docker_args.append(image)

        _append_command_args(docker_args, runtime.get("command", []), format_context)

        return docker_args, runtime_settings

    def _verify_started_container(
        self,
        container_name: str,
        runtime: dict[str, object],
        runtime_settings: dict[str, object],
    ) -> None:
        """Verify a container is still alive before recording it as running.

        This closes the gap between "docker run returned 0" and "the honeypot
        is actually alive". Some third-party images exit immediately after the
        shell command starts. Without this check, the orchestrator would record
        a dead asset as `running`, which is exactly the confusing Redis case.
        """
        attempts = 6
        delay_seconds = 0.5
        last_status = "missing"

        for _ in range(attempts):
            last_status = _container_status(container_name)
            if last_status.startswith("Up"):
                if _healthcheck_ready(runtime, runtime_settings):
                    return
            elif last_status.startswith(("Exited", "Dead")):
                break
            time.sleep(delay_seconds)

        self._cleanup_failed_container(container_name)
        raise RuntimeError(
            f"container {container_name} failed startup verification (status={last_status})"
        )

    def _cleanup_failed_container(self, container_name: str) -> None:
        """Best-effort cleanup after a failed startup verification."""
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            capture_output=True,
            text=True,
        )

    def _start_sidecar_forwarders(
        self,
        *,
        binding_id: str,
        asset: AssetDefinition,
        runtime: dict[str, object],
        main_container_name: str,
        attacker_key: str | None,
    ) -> list[str]:
        """Start catalog-declared log forwarders next to a runtime container.

        Sidecars are used for high-interaction backends that write local log
        files but do not know how to call the honeynet adapters themselves. The
        sidecar mounts the same runtime log directory, joins the control
        network, and runs a forwarder such as `scripts/forwarders/cowrie_json.py`
        or `scripts/forwarders/high_interaction_logs.py`.

        Example:
            runtime.sidecar_forwarders=[{"name":"cowrie-forwarder","image":"python:3.10-slim", ...}]
            -> ["honeynet-abcd1234-admin-jumpbox-cowrie-forwarder"]
        """
        sidecars = runtime.get("sidecar_forwarders", [])
        if not isinstance(sidecars, list):
            return []

        started: list[str] = []
        format_context = {
            **_runtime_format_context(binding_id, asset.asset_id),
            "main_container_name": main_container_name,
            "attacker_key": attacker_key or "",
        }
        for sidecar in sidecars:
            if not isinstance(sidecar, dict):
                continue
            sidecar_name = _sidecar_container_name(
                binding_id,
                asset.asset_id,
                str(sidecar.get("name", "forwarder")),
            )
            status = _container_status(sidecar_name)
            if status.startswith("Up"):
                started.append(sidecar_name)
                continue
            if status != "missing":
                self._cleanup_failed_container(sidecar_name)
            sidecar_args = _sidecar_docker_args(
                binding_id=binding_id,
                asset=asset,
                sidecar=sidecar,
                sidecar_name=sidecar_name,
                format_context=format_context,
            )
            subprocess.run(
                sidecar_args,
                check=True,
                capture_output=True,
                text=True,
            )
            if not _container_status(sidecar_name).startswith("Up"):
                self._cleanup_failed_container(sidecar_name)
                raise RuntimeError(f"sidecar {sidecar_name} failed startup verification")
            started.append(sidecar_name)
        return started

    def _record_running_container(
        self,
        *,
        binding_id: str,
        asset: AssetDefinition,
        runtime_settings: dict[str, object],
        asset_gateway_managed: bool,
        attacker_key: str | None,
        container_name: str,
    ) -> AssetRuntimeRecord:
        """Persist metadata for a container that is already confirmed running."""
        if asset_gateway_managed:
            backend_ip = _container_network_ip(
                container_name,
                str(runtime_settings.get("network", "")),
            )
            if backend_ip:
                runtime_settings["backend_ip"] = backend_ip

        settings = dict(asset.default_settings)
        settings.update(runtime_settings)
        record = _runtime_record_from_asset(binding_id, asset, settings=settings)
        if asset_gateway_managed and attacker_key:
            upsert_asset_gateway_routes(
                binding_id=binding_id,
                attacker_key=attacker_key,
                asset=asset,
                runtime_settings=runtime_settings,
            )
        return self._repository.upsert(record)


class ComposeTemplateRuntime:
    """Start a compose-backed internal asset declared by the catalog."""

    def __init__(
        self,
        repository: TemplateRuntimeRepository,
    ) -> None:
        self._repository = repository

    def supports(self, asset: AssetDefinition) -> bool:
        runtime = asset.default_settings.get("runtime", {})
        return isinstance(runtime, dict) and runtime.get("backend") == "compose"

    def start_asset(
        self,
        binding_id: str,
        asset: AssetDefinition,
        attacker_key: str | None = None,
    ) -> AssetRuntimeRecord:
        """Start one supported asset through Docker Compose."""
        existing = _existing_running_record(self._repository, binding_id, asset.asset_id)
        if existing is not None:
            return existing

        if shutil.which("docker") is None:
            raise RuntimeError("docker CLI is not available on this host")
        if not self.supports(asset):
            raise RuntimeError(f"asset {asset.asset_id} is not supported by ComposeTemplateRuntime")

        runtime = dict(asset.default_settings.get("runtime", {}))
        compose_file = _resolve_compose_file(runtime)
        compose_project = _compose_project_name(binding_id, asset.asset_id, runtime)

        subprocess.run(
            _compose_command(runtime, compose_file, compose_project, ["up", "-d"]),
            check=True,
            capture_output=True,
            text=True,
        )

        container_ids = _compose_container_ids(runtime, compose_file, compose_project)
        internal_network = _compose_internal_network(runtime)
        if internal_network:
            _connect_containers_to_network(container_ids, internal_network)

        statuses = _compose_project_statuses(compose_project)
        if not statuses or not all(status.startswith("Up") for status in statuses.values()):
            _compose_down(runtime, compose_file, compose_project)
            raise RuntimeError(
                f"compose project {compose_project} failed startup verification"
            )

        runtime_settings = {
            "runtime_backend": "compose",
            "compose_file": str(compose_file),
            "compose_project": compose_project,
            "container_ids": container_ids,
            "container_names": list(statuses.keys()),
            "container_statuses": statuses,
            "internal_network": internal_network,
            "source": runtime.get("source", ""),
        }
        target_container = _compose_gateway_target_container(
            runtime,
            compose_project,
            statuses,
        )
        if target_container:
            port_records = resolve_port_mappings(
                runtime,
                asset.asset_id,
                asset_gateway_managed=True,
                backend_host=target_container,
            )
            if port_records:
                first_port = port_records[0]
                runtime_settings.update(
                    {
                        "asset_gateway_managed": True,
                        "target_container": target_container,
                        "backend_host": target_container,
                        "backend_port": first_port["container_port"],
                        "public_port": first_port["host_port"],
                        "port_mappings": port_records,
                    }
                )
                backend_ip = _container_network_ip(target_container, internal_network)
                if backend_ip:
                    runtime_settings["backend_ip"] = backend_ip
        settings = dict(asset.default_settings)
        settings.update(runtime_settings)
        record = _runtime_record_from_asset(binding_id, asset, settings=settings)
        if attacker_key and runtime_settings.get("asset_gateway_managed") is True:
            upsert_asset_gateway_routes(
                binding_id=binding_id,
                attacker_key=attacker_key,
                asset=asset,
                runtime_settings=runtime_settings,
            )
        return self._repository.upsert(record)

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Convert a Compose runtime record into a Falco-style lifecycle event."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop all running Compose-backed assets for one binding."""
        stopped: list[AssetRuntimeRecord] = []
        for record in self._repository.list_by_binding(binding_id):
            if record.status != "running":
                continue
            if str(record.settings.get("runtime_backend", "mock")) != "compose":
                continue
            runtime = _runtime_from_record(record)
            raw_compose_file = str(record.settings.get("compose_file", "")).strip()
            compose_project = str(record.settings.get("compose_project", ""))
            if raw_compose_file and compose_project:
                _compose_down(runtime, Path(raw_compose_file), compose_project)
            updated = record.model_copy(update={"status": "stopped"})
            self._repository.upsert(updated)
            stopped.append(updated)
        return stopped

    def list_accessible_asset_ids(self, binding_id: str) -> list[str]:
        """Return Compose assets whose project containers are still Up."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if _compose_record_is_accessible(record):
                asset_ids.append(record.asset_id)
        return asset_ids

    def list_failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return Compose assets whose project failed or exited."""
        asset_ids: list[str] = []
        for record in self._repository.list_by_binding(binding_id):
            if _compose_record_is_failed(record):
                asset_ids.append(record.asset_id)
        return asset_ids


class HybridTemplateRuntime:
    """Prefer Docker when possible, otherwise fall back to the mock runtime."""

    def __init__(
        self,
        docker_runtime: DockerTemplateRuntime,
        mock_runtime: MockTemplateRuntime,
        compose_runtime: ComposeTemplateRuntime | None = None,
    ) -> None:
        self._docker_runtime = docker_runtime
        self._mock_runtime = mock_runtime
        self._compose_runtime = compose_runtime

    def start_asset(
        self,
        binding_id: str,
        asset: AssetDefinition,
        attacker_key: str | None = None,
    ) -> AssetRuntimeRecord:
        """Start with Docker when supported, otherwise return a mock record."""
        if self._compose_runtime is not None and self._compose_runtime.supports(asset):
            try:
                return self._compose_runtime.start_asset(binding_id, asset, attacker_key)
            except Exception as exc:
                failed = _runtime_record_from_asset(
                    binding_id,
                    asset,
                    settings={
                        **dict(asset.default_settings),
                        "runtime_backend": "compose",
                        "runtime_failure": str(exc),
                    },
                ).model_copy(update={"status": "failed"})
                return self._mock_runtime.upsert_record(failed)
        if self._docker_runtime.supports(asset):
            try:
                return self._docker_runtime.start_asset(binding_id, asset, attacker_key)
            except Exception as exc:
                failed = _runtime_record_from_asset(
                    binding_id,
                    asset,
                    settings={
                        **dict(asset.default_settings),
                        "runtime_backend": "docker",
                        "runtime_failure": str(exc),
                    },
                ).model_copy(update={"status": "failed"})
                return self._mock_runtime.upsert_record(failed)
        return self._mock_runtime.start_asset(binding_id, asset, attacker_key)

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Return a lifecycle event for either Docker or mock records."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def apply_configuration(
        self,
        binding_id: str,
        asset_id: str,
        configuration_id: str,
        configuration: dict[str, object],
    ) -> AssetRuntimeRecord | None:
        """Record an A.2 configuration reveal on the source asset runtime."""
        return self._mock_runtime.apply_configuration(
            binding_id,
            asset_id,
            configuration_id,
            configuration,
        )

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop Docker-backed records and then stop any remaining mock records."""
        stopped: list[AssetRuntimeRecord] = []
        if self._compose_runtime is not None:
            stopped.extend(self._compose_runtime.stop_binding_assets(binding_id))
        stopped.extend(self._docker_runtime.stop_binding_assets(binding_id))
        stopped.extend(self._mock_runtime.stop_binding_assets(binding_id))
        deduped: dict[str, AssetRuntimeRecord] = {record.runtime_id: record for record in stopped}
        return list(deduped.values())

    def list_accessible_asset_ids(self, binding_id: str) -> list[str]:
        """Return the union of currently reachable Docker and mock assets."""
        asset_ids: list[str] = []
        if self._compose_runtime is not None:
            asset_ids.extend(self._compose_runtime.list_accessible_asset_ids(binding_id))
        asset_ids.extend(self._docker_runtime.list_accessible_asset_ids(binding_id))
        asset_ids.extend(self._mock_runtime.list_accessible_asset_ids(binding_id))
        return dedupe_preserve(asset_ids)

    def list_failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return the union of failed Docker and mock assets."""
        asset_ids: list[str] = []
        if self._compose_runtime is not None:
            asset_ids.extend(self._compose_runtime.list_failed_asset_ids(binding_id))
        asset_ids.extend(self._docker_runtime.list_failed_asset_ids(binding_id))
        asset_ids.extend(self._mock_runtime.list_failed_asset_ids(binding_id))
        return dedupe_preserve(asset_ids)


def _runtime_record_from_asset(
    binding_id: str,
    asset: AssetDefinition,
    settings: dict[str, object] | None = None,
) -> AssetRuntimeRecord:
    """Build the shared runtime record shape for either mock or Docker starts."""
    return AssetRuntimeRecord(
        runtime_id=str(uuid4()),
        binding_id=binding_id,
        asset_id=asset.asset_id,
        asset_name=asset.asset_name,
        template_family=asset.template_family,
        status="running",
        protocols=list(asset.protocols),
        ports=list(asset.ports),
        settings=settings if settings is not None else dict(asset.default_settings),
        source_refs=list(asset.source_refs),
        started_at=utcnow(),
    )


def _existing_running_record(
    repository: TemplateRuntimeRepository,
    binding_id: str,
    asset_id: str,
) -> AssetRuntimeRecord | None:
    """Return the existing running runtime for an idempotent asset start.

    Example:
        repository has running asset_id="dionaea-capture" for binding b1 -> that
        record is reused instead of starting another container.
    """
    for record in repository.list_by_binding(binding_id):
        if record.asset_id == asset_id and record.status == "running":
            return record
    return None


def _apply_configuration_to_record(
    repository: TemplateRuntimeRepository,
    binding_id: str,
    asset_id: str,
    configuration_id: str,
    configuration: dict[str, object],
) -> AssetRuntimeRecord | None:
    """Attach a follow-on configuration reveal to the source runtime record."""
    record = _existing_running_record(repository, binding_id, asset_id)
    if record is None:
        return None
    active = record.settings.get("active_configurations", {})
    active_configurations = dict(active) if isinstance(active, dict) else {}
    active_configurations[configuration_id] = configuration
    updated_settings = {
        **record.settings,
        "active_configurations": active_configurations,
    }
    updated = record.model_copy(update={"settings": updated_settings})
    return repository.upsert(updated)


def _monitoring_event_for_record(
    record: AssetRuntimeRecord,
    lifecycle: str,
) -> FalcoEvent:
    """Translate runtime lifecycle into the normalized FalcoEvent contract."""
    return FalcoEvent(
        ts=record.started_at,
        falco_rule=f"Honeynet asset template {lifecycle}",
        priority="INFO",
        output=(
            f"asset {record.asset_id} {lifecycle} for binding {record.binding_id} "
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


def _container_name(binding_id: str, asset_id: str) -> str:
    """Generate a stable Docker container name for one binding+asset pair."""
    return f"honeynet-{binding_id[:8]}-{asset_id}"


def _sidecar_container_name(binding_id: str, asset_id: str, sidecar_name: str) -> str:
    """Generate a stable Docker name for one runtime sidecar.

    Example:
        binding=abcdef1234, asset=admin-jumpbox, sidecar=cowrie-forwarder
        -> honeynet-abcdef12-admin-jumpbox-cowrie-forwarder
    """
    safe_sidecar = "".join(
        char if char.isalnum() or char == "-" else "-"
        for char in sidecar_name.lower()
    ).strip("-")
    return f"honeynet-{binding_id[:8]}-{asset_id}-{safe_sidecar or 'forwarder'}"


def _sidecar_docker_args(
    *,
    binding_id: str,
    asset: AssetDefinition,
    sidecar: dict[str, object],
    sidecar_name: str,
    format_context: dict[str, str],
) -> list[str]:
    """Build a `docker run` command for one log-forwarding sidecar.

    Example input:
        {"image": "python:3.10-slim", "command": ["python", "scripts/forwarders/..."]}
    Example output:
        ["docker", "run", "-d", "--name", "honeynet-...", "--label", ...]
    """
    image = sidecar.get("image")
    if not isinstance(image, str) or not image.strip():
        raise RuntimeError(f"sidecar for {asset.asset_id} is missing image")

    args = [
        "docker",
        "run",
        "-d",
        "--name",
        sidecar_name,
        "--label",
        "honeynet.mvp=true",
        "--label",
        "honeynet.sidecar=true",
        "--label",
        f"honeynet.binding_id={binding_id}",
        "--label",
        f"honeynet.asset_id={asset.asset_id}",
    ]

    network = sidecar.get("network")
    if isinstance(network, str) and network.strip():
        args.extend(["--network", _format_runtime_string(network.strip(), format_context)])

    _append_runtime_string_option(args, {}, sidecar, "working_dir", "-w", format_context)
    _append_runtime_list_option(args, {}, sidecar, "volumes", "-v", format_context)
    _append_env_args(args, sidecar.get("env", {}), format_context)

    args.append(image.strip())

    _append_command_args(args, sidecar.get("command", []), format_context)
    return args


def _append_runtime_string_option(
    args: list[str],
    settings: dict[str, object],
    spec: dict[str, object],
    key: str,
    flag: str,
    context: dict[str, str],
) -> None:
    """Append one optional Docker string flag from a catalog runtime spec.

    Example:
        key="working_dir", flag="-w", value="/app" -> args += ["-w", "/app"].
        When `settings` is non-empty, the normalized value is stored there too.
    """
    value = spec.get(key)
    if not isinstance(value, str) or not value.strip():
        return
    formatted = _format_runtime_string(value.strip(), context)
    args.extend([flag, formatted])
    settings[key] = formatted


def _append_runtime_list_option(
    args: list[str],
    settings: dict[str, object],
    spec: dict[str, object],
    key: str,
    flag: str,
    context: dict[str, str] | None = None,
) -> None:
    """Append repeated Docker flags from a catalog list.

    Example:
        key="cap_drop", flag="--cap-drop", values=["ALL"]
        -> args += ["--cap-drop", "ALL"], settings["cap_drop"] = ["ALL"].

    `context` is only needed for path-like values such as volume mounts that
    use placeholders like `{host_project_root}`.
    """
    values = spec.get(key, [])
    if not isinstance(values, list):
        return
    normalized: list[str] = []
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        if context is not None:
            item = _format_runtime_string(item, context)
        args.extend([flag, item])
        normalized.append(item)
    if normalized:
        settings[key] = normalized


def _prepare_runtime_volume_sources(
    runtime: dict[str, object],
    context: dict[str, str],
) -> None:
    """Create writable host log directories before Docker bind-mounts them.

    Some high-interaction images drop privileges after startup. If Docker creates
    the bind source implicitly, it is root-owned and those backends cannot write
    their JSON/text logs. Limit the chmod to runtime artifact directories so
    catalog config files and repo source mounts are left untouched.
    """
    volumes = runtime.get("volumes", [])
    if not isinstance(volumes, list):
        return
    for raw_volume in volumes:
        volume = _format_runtime_string(str(raw_volume), context)
        source = volume.split(":", 1)[0]
        if "/data/runtime/high_interaction/" not in source:
            continue
        local_source = _container_visible_host_path(source, context)
        path = Path(local_source)
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o777)


def _container_visible_host_path(source: str, context: dict[str, str]) -> str:
    """Map a Docker host bind path back to the orchestrator-visible mount path."""
    host_root = context.get("host_project_root", "")
    container_root = context.get("container_project_root", "")
    if host_root and container_root and source.startswith(host_root):
        return f"{container_root}{source[len(host_root):]}"
    return source


def _append_env_args(
    args: list[str],
    env: object,
    context: dict[str, str],
) -> None:
    """Append Docker `-e KEY=value` flags from a catalog env mapping.

    Example:
        {"PYTHONPATH": "{container_project_root}"} -> ["-e", "PYTHONPATH=/app"].
    """
    if not isinstance(env, dict):
        return
    for key, value in env.items():
        formatted_value = _format_runtime_string(str(value), context)
        args.extend(["-e", f"{key}={formatted_value}"])


def _append_command_args(
    args: list[str],
    command: object,
    context: dict[str, str],
) -> None:
    """Append the container command after the image name.

    Example:
        ["python", "{container_project_root}/script.py"] -> ["python", "/app/script.py"].
    """
    if isinstance(command, list):
        args.extend(_format_runtime_string(str(part), context) for part in command)
    elif isinstance(command, str) and command:
        args.append(_format_runtime_string(command, context))


def _runtime_format_context(binding_id: str, asset_id: str) -> dict[str, str]:
    """Return placeholders supported in catalog Docker runtime strings."""
    return {
        "binding_id": binding_id,
        "binding_id_short": binding_id[:8],
        "asset_id": asset_id,
        "project_name": _honeynet_project_name(),
        "container_project_root": str(_container_project_root()),
        "host_project_root": str(_host_project_root()),
    }


def _format_runtime_string(value: str, context: dict[str, str]) -> str:
    """Format one catalog runtime string with a clear error on bad placeholders."""
    try:
        return value.format(**context)
    except KeyError as exc:
        raise RuntimeError(f"unknown runtime placeholder: {exc.args[0]}") from exc


def _docker_run_error_message(exc: subprocess.CalledProcessError) -> str:
    """Return a useful Docker run error without losing stderr details."""
    details = (exc.stderr or exc.stdout or str(exc)).strip()
    return f"docker run failed with exit status {exc.returncode}: {details}"


def _container_network_ip(container_name: str, network_name: str) -> str | None:
    """Return the container IP on the runtime network when Docker exposes it."""
    result = subprocess.run(
        ["docker", "inspect", container_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    container = payload[0]
    if not isinstance(container, dict):
        return None
    network_settings = container.get("NetworkSettings", {})
    if not isinstance(network_settings, dict):
        return None
    networks = network_settings.get("Networks", {})
    if not isinstance(networks, dict):
        return None
    if network_name and isinstance(networks.get(network_name), dict):
        ip_address = networks[network_name].get("IPAddress")
        if isinstance(ip_address, str) and ip_address:
            return ip_address
    for network in networks.values():
        if not isinstance(network, dict):
            continue
        ip_address = network.get("IPAddress")
        if isinstance(ip_address, str) and ip_address:
            return ip_address
    return None


def _resolve_compose_file(runtime: dict[str, object]) -> Path:
    """Resolve and verify a compose file declared by an asset runtime."""
    raw_compose_file = runtime.get("compose_file")
    if not isinstance(raw_compose_file, str) or not raw_compose_file.strip():
        raise RuntimeError("compose runtime is missing compose_file")
    compose_file = Path(raw_compose_file)
    if not compose_file.is_absolute():
        compose_file = _container_project_root() / compose_file
    if not compose_file.exists():
        raise RuntimeError(f"compose file does not exist: {compose_file}")
    return compose_file


def _compose_project_name(
    binding_id: str,
    asset_id: str,
    runtime: dict[str, object],
) -> str:
    """Return a deterministic Compose project name for one binding+asset."""
    context = {
        "binding_id": binding_id,
        "binding_id_short": binding_id[:8],
        "asset_id": asset_id,
        "project_name": _honeynet_project_name(),
    }
    template = runtime.get("project_name")
    if not isinstance(template, str) or not template.strip():
        template = "honeynet-{binding_id_short}-{asset_id}"
    return _compose_safe_name(template.format(**context))


def _compose_safe_name(value: str) -> str:
    """Normalize a string so Docker Compose accepts it as a project name."""
    normalized = []
    for char in value.lower():
        if char.isalnum():
            normalized.append(char)
        elif char in {"-", "_"}:
            normalized.append(char)
        else:
            normalized.append("-")
    safe = "".join(normalized).strip("-_")
    return safe or "honeynet-asset"


def _compose_command(
    runtime: dict[str, object],
    compose_file: Path,
    compose_project: str,
    compose_args: list[str],
) -> list[str]:
    """Build a Compose command using either local compose or docker/compose."""
    runner = str(
        runtime.get("runner")
        or os.environ.get("HONEYPOT_COMPOSE_RUNNER", "docker_image")
    ).strip()
    if runner == "local":
        return _local_compose_command(compose_file, compose_project, compose_args)
    return _docker_image_compose_command(runtime, compose_file, compose_project, compose_args)


def _local_compose_command(
    compose_file: Path,
    compose_project: str,
    compose_args: list[str],
) -> list[str]:
    """Build a host-local Docker Compose command."""
    if shutil.which("docker-compose"):
        base = ["docker-compose"]
    else:
        base = ["docker", "compose"]
    return [
        *base,
        "-p",
        compose_project,
        "-f",
        str(compose_file),
        *compose_args,
    ]


def _docker_image_compose_command(
    runtime: dict[str, object],
    compose_file: Path,
    compose_project: str,
    compose_args: list[str],
) -> list[str]:
    """Run Compose through a Docker image so the orchestrator container can use it."""
    container_root = _container_project_root()
    host_root = _host_project_root()
    try:
        relative_compose_file = compose_file.resolve().relative_to(container_root)
    except ValueError as exc:
        raise RuntimeError(
            f"compose file {compose_file} is not under HONEYPOT_PROJECT_ROOT_IN_CONTAINER={container_root}"
        ) from exc

    compose_image = str(runtime.get("compose_image", "docker/compose:1.29.2"))
    compose_workdir = Path("/workspace") / relative_compose_file.parent
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        f"{host_root}:/workspace",
        "-w",
        str(compose_workdir),
        compose_image,
        "-p",
        compose_project,
        "-f",
        relative_compose_file.name,
        *compose_args,
    ]


def _compose_container_ids(
    runtime: dict[str, object],
    compose_file: Path,
    compose_project: str,
) -> list[str]:
    """Return container ids created for a Compose project."""
    result = subprocess.run(
        _compose_command(runtime, compose_file, compose_project, ["ps", "-q"]),
        check=True,
        capture_output=True,
        text=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _compose_down(
    runtime: dict[str, object],
    compose_file: Path,
    compose_project: str,
) -> None:
    """Best-effort Compose project cleanup."""
    subprocess.run(
        _compose_command(runtime, compose_file, compose_project, ["down", "--remove-orphans"]),
        check=False,
        capture_output=True,
        text=True,
    )


def _compose_internal_network(runtime: dict[str, object]) -> str:
    """Resolve the Docker network used to attach internal compose assets."""
    raw_network = runtime.get("internal_network", "{project_name}_net_internal")
    if raw_network is False:
        return ""
    if not isinstance(raw_network, str) or not raw_network.strip():
        return ""
    return raw_network.format(project_name=_honeynet_project_name())


def _connect_containers_to_network(
    container_ids: list[str],
    network_name: str,
) -> None:
    """Attach compose containers to the honeynet internal network when possible."""
    if not container_ids or not network_name:
        return
    if not _docker_network_exists(network_name):
        raise RuntimeError(f"internal network does not exist: {network_name}")
    for container_id in container_ids:
        if _container_attached_to_network(container_id, network_name):
            continue
        subprocess.run(
            ["docker", "network", "connect", network_name, container_id],
            check=True,
            capture_output=True,
            text=True,
        )


def _docker_network_exists(network_name: str) -> bool:
    """Return True when Docker knows about a network."""
    result = subprocess.run(
        ["docker", "network", "inspect", network_name],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _container_attached_to_network(container_id: str, network_name: str) -> bool:
    """Return True when a container is already attached to a network."""
    result = subprocess.run(
        [
            "docker",
            "inspect",
            container_id,
            "--format",
            "{{json .NetworkSettings.Networks}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and f'"{network_name}"' in result.stdout


def _compose_project_statuses(compose_project: str) -> dict[str, str]:
    """Return current Docker statuses for all containers in a Compose project."""
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={compose_project}",
            "--format",
            "{{.Names}}\t{{.Status}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return {}
    statuses: dict[str, str] = {}
    for line in result.stdout.splitlines():
        name, separator, status = line.partition("\t")
        if separator and name:
            statuses[name] = status
    return statuses


def _compose_gateway_target_container(
    runtime: dict[str, object],
    compose_project: str,
    statuses: dict[str, str],
) -> str:
    """Return the compose container name that asset-gateway should proxy to.

    Example:
        gateway_target_service="app" with container "honeynet-x-app-1" -> that name.
    """
    target_service = str(runtime.get("gateway_target_service", "")).strip()
    if target_service:
        labelled = _compose_container_name_for_service(compose_project, target_service)
        if labelled:
            return labelled
        for name in statuses:
            normalized = name.replace("-", "_")
            if f"_{target_service}_" in normalized or f"-{target_service}-" in name:
                return name
    gateway_target_container = str(runtime.get("gateway_target_container", "")).strip()
    if gateway_target_container:
        return gateway_target_container
    return next(iter(statuses), "")


def _compose_container_name_for_service(compose_project: str, service: str) -> str:
    """Ask Docker for the container name behind one compose service label.

    Example:
        project=honeynet-abcd-compose-web-lab, service=app -> honeynet-abcd-compose-web-lab-app-1
    """
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={compose_project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--format",
            "{{.Names}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return ""
    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), "")


def _runtime_from_record(record: AssetRuntimeRecord) -> dict[str, object]:
    """Rebuild a minimal runtime dict from a persisted compose runtime record."""
    runtime = record.settings.get("runtime", {})
    if isinstance(runtime, dict):
        return dict(runtime)
    return {
        "backend": "compose",
        "compose_file": record.settings.get("compose_file", ""),
    }


def _compose_record_is_accessible(record: AssetRuntimeRecord) -> bool:
    """Return True when a compose-backed runtime should count as reachable."""
    if record.status != "running":
        return False
    if str(record.settings.get("runtime_backend", "mock")) != "compose":
        return False
    compose_project = record.settings.get("compose_project")
    if not isinstance(compose_project, str) or not compose_project:
        return False
    statuses = _compose_project_statuses(compose_project)
    return bool(statuses) and all(status.startswith("Up") for status in statuses.values())


def _compose_record_is_failed(record: AssetRuntimeRecord) -> bool:
    """Return True when a compose-backed runtime has failed or disappeared."""
    if record.status == "failed":
        return str(record.settings.get("runtime_backend", "mock")) == "compose"
    if record.status != "running":
        return False
    if str(record.settings.get("runtime_backend", "mock")) != "compose":
        return False
    compose_project = record.settings.get("compose_project")
    if not isinstance(compose_project, str) or not compose_project:
        return True
    statuses = _compose_project_statuses(compose_project)
    return not statuses or any(not status.startswith("Up") for status in statuses.values())


def _honeynet_project_name() -> str:
    """Return the compose project name used by the surrounding honeynet."""
    return os.environ.get("HONEYPOT_PROJECT_NAME", "honeynet")


def _container_project_root() -> Path:
    """Return the repository path visible inside the orchestrator process."""
    return Path(
        os.environ.get("HONEYPOT_PROJECT_ROOT_IN_CONTAINER", str(Path.cwd()))
    ).resolve()


def _host_project_root() -> Path:
    """Return the repository path visible to the host Docker daemon."""
    raw_path = os.environ.get("HONEYPOT_HOST_PROJECT_ROOT", "").strip()
    if raw_path and raw_path != "." and "$" not in raw_path:
        return Path(raw_path).resolve()
    inferred = _host_mount_source_for_container_path(_container_project_root())
    if inferred is not None:
        return inferred
    if raw_path:
        return Path(raw_path).resolve()
    return _container_project_root()


def _host_mount_source_for_container_path(container_path: Path) -> Path | None:
    """Infer the host bind-mount source for the orchestrator repo mount.

    This keeps Docker-backed assets working even when the stack was started
    directly with compose and `HOST_PROJECT_ROOT` was not exported.
    """
    container_id = os.environ.get("HOSTNAME", "").strip()
    if not container_id or shutil.which("docker") is None:
        return None
    result = subprocess.run(
        ["docker", "inspect", container_id],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    mounts = payload[0].get("Mounts", []) if isinstance(payload[0], dict) else []
    if not isinstance(mounts, list):
        return None
    container_path_text = str(container_path)
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        if str(mount.get("Destination", "")) != container_path_text:
            continue
        source = str(mount.get("Source", "")).strip()
        if source:
            return Path(source).resolve()
    return None


def _container_status(container_name: str) -> str:
    """Return the current Docker status string for one container name."""
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"name={container_name}",
            "--format",
            "{{.Status}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "missing"
    statuses = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return statuses[0] if statuses else "missing"


def _healthcheck_ready(
    runtime: dict[str, object],
    runtime_settings: dict[str, object],
) -> bool:
    """Return True when the configured runtime health check passes.

    If a template does not declare a health check, container liveness alone is
    enough for the MVP. For TCP-backed honeypots we can cheaply verify that the
    mapped localhost port is actually listening before we claim success.
    """
    if _skip_runtime_tcp_healthcheck():
        return True

    healthcheck = runtime.get("healthcheck")
    if not isinstance(healthcheck, dict):
        return True
    if runtime_settings.get("asset_gateway_managed") is True:
        return True

    if healthcheck.get("type") != "tcp":
        return True

    host = str(healthcheck.get("host", runtime_settings.get("host", "127.0.0.1")))
    if healthcheck.get("port_setting") == "host_port":
        port = runtime_settings.get("host_port")
    else:
        port = healthcheck.get("port")
    if not isinstance(port, int):
        return False
    return _tcp_port_accepts_connections(host, port)


def _skip_runtime_tcp_healthcheck() -> bool:
    """Allow compose-contained orchestrators to trust Docker container liveness."""
    value = os.environ.get("HONEYPOT_SKIP_RUNTIME_TCP_HEALTHCHECK", "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _runtime_record_is_accessible(record: AssetRuntimeRecord) -> bool:
    """Return True when a runtime record should count as reachable now."""
    if record.status != "running":
        return False
    backend = str(record.settings.get("runtime_backend", "mock"))
    if backend != "docker":
        return True
    container_name = record.settings.get("container_name")
    if not isinstance(container_name, str) or not container_name:
        return False
    return _container_status(container_name).startswith("Up")


def _runtime_record_is_failed(record: AssetRuntimeRecord) -> bool:
    """Return True when a runtime record should count as failed now."""
    if record.status == "failed":
        return True
    if record.status != "running":
        return False
    backend = str(record.settings.get("runtime_backend", "mock"))
    if backend != "docker":
        return False
    container_name = record.settings.get("container_name")
    if not isinstance(container_name, str) or not container_name:
        return True
    status = _container_status(container_name)
    return bool(status) and not status.startswith("Up")


def _tcp_port_accepts_connections(host: str, port: int) -> bool:
    """Return True when a TCP connect to host:port succeeds right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((host, port))
        except OSError:
            return False
    return True
