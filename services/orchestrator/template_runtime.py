"""Template runtime adapters for enabled decoy assets.

This module separates "controller chose an asset" from "something concrete was
started for that asset". The current MVP supports:

- a mock runtime that only records the start plan
- a Docker-backed runtime for a small safe subset of templates

Both runtimes emit Falco-style lifecycle events so the rest of the prototype
can observe template starts/stops before real Falco container telemetry is
wired in.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
import shutil
import socket
import subprocess
import time
from typing import Protocol
from uuid import uuid4

from libs.common.clock import utcnow
from libs.common.json_store import JsonFileStore
from libs.contracts.models import AssetDefinition, AssetRuntimeRecord, FalcoEvent


class TemplateRuntimeRepository(Protocol):
    """Storage contract for asset runtime records."""

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        """Insert or update one asset runtime record."""
        ...

    def list_by_binding(self, binding_id: str) -> Iterable[AssetRuntimeRecord]:
        """Return runtime records associated with one binding."""
        ...


class InMemoryTemplateRuntimeRepository:
    """In-memory runtime store used by tests."""

    def __init__(self) -> None:
        self._records: dict[str, AssetRuntimeRecord] = {}

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        self._records[record.runtime_id] = record
        return record

    def list_by_binding(self, binding_id: str) -> Iterable[AssetRuntimeRecord]:
        return tuple(
            record
            for record in self._records.values()
            if record.binding_id == binding_id
        )


class FileTemplateRuntimeRepository:
    """File-backed runtime store for default local orchestration."""

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"records": []})

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        payload = self._store.read()
        records = {
            item["runtime_id"]: AssetRuntimeRecord.model_validate(item)
            for item in payload.get("records", [])
        }
        records[record.runtime_id] = record
        payload["records"] = [
            item.model_dump(mode="json")
            for item in records.values()
        ]
        self._store.write(payload)
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
    ) -> AssetRuntimeRecord:
        """Record that an asset is running with its catalog default settings."""
        existing = self._existing_record(binding_id, asset.asset_id)
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

    def _existing_record(
        self,
        binding_id: str,
        asset_id: str,
    ) -> AssetRuntimeRecord | None:
        for record in self._repository.list_by_binding(binding_id):
            if record.asset_id == asset_id and record.status == "running":
                return record
        return None


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
    ) -> AssetRuntimeRecord:
        """Start one supported asset as a real Docker container."""
        existing = self._existing_record(binding_id, asset.asset_id)
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
        docker_args, runtime_settings = self._docker_args_for_runtime(
            binding_id,
            asset,
            runtime,
            container_name,
            image,
        )

        subprocess.run(
            docker_args,
            check=True,
            capture_output=True,
            text=True,
        )
        self._verify_started_container(
            container_name=container_name,
            runtime=runtime,
            runtime_settings=runtime_settings,
        )

        settings = dict(asset.default_settings)
        settings.update(runtime_settings)
        record = _runtime_record_from_asset(binding_id, asset, settings=settings)
        return self._repository.upsert(record)

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Convert a Docker runtime record into a Falco-style lifecycle event."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop all running Docker-backed assets for one binding."""
        stopped: list[AssetRuntimeRecord] = []
        for record in self._repository.list_by_binding(binding_id):
            if record.status != "running":
                continue
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

        cap_add = runtime.get("cap_add", [])
        if isinstance(cap_add, list):
            normalized_caps: list[str] = []
            for cap in cap_add:
                cap_name = str(cap).strip()
                if not cap_name:
                    continue
                docker_args.extend(["--cap-add", cap_name])
                normalized_caps.append(cap_name)
            if normalized_caps:
                runtime_settings["cap_add"] = normalized_caps

        read_only = runtime.get("read_only")
        if isinstance(read_only, bool) and read_only:
            docker_args.append("--read-only")
            runtime_settings["read_only"] = True

        tmpfs_mounts = runtime.get("tmpfs", [])
        if isinstance(tmpfs_mounts, list):
            normalized_tmpfs: list[str] = []
            for mount in tmpfs_mounts:
                mount_path = str(mount).strip()
                if not mount_path:
                    continue
                docker_args.extend(["--tmpfs", mount_path])
                normalized_tmpfs.append(mount_path)
            if normalized_tmpfs:
                runtime_settings["tmpfs"] = normalized_tmpfs

        volumes = runtime.get("volumes", [])
        if isinstance(volumes, list):
            normalized_volumes: list[str] = []
            for volume in volumes:
                mount = str(volume).strip()
                if not mount:
                    continue
                docker_args.extend(["-v", mount])
                normalized_volumes.append(mount)
            if normalized_volumes:
                runtime_settings["volumes"] = normalized_volumes

        port_records = _resolve_port_mappings(runtime)
        for port_record in port_records:
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

        env = runtime.get("env", {})
        if isinstance(env, dict):
            for key, value in env.items():
                docker_args.extend(["-e", f"{key}={value}"])

        entrypoint = runtime.get("entrypoint")
        if isinstance(entrypoint, str) and entrypoint:
            docker_args.extend(["--entrypoint", entrypoint])

        docker_args.append(image)

        command = runtime.get("command", [])
        if isinstance(command, list):
            docker_args.extend(str(part) for part in command)
        elif isinstance(command, str) and command:
            docker_args.append(command)

        return docker_args, runtime_settings

    def _existing_record(
        self,
        binding_id: str,
        asset_id: str,
    ) -> AssetRuntimeRecord | None:
        for record in self._repository.list_by_binding(binding_id):
            if record.asset_id == asset_id and record.status == "running":
                return record
        return None

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


class HybridTemplateRuntime:
    """Prefer Docker when possible, otherwise fall back to the mock runtime."""

    def __init__(
        self,
        docker_runtime: DockerTemplateRuntime,
        mock_runtime: MockTemplateRuntime,
    ) -> None:
        self._docker_runtime = docker_runtime
        self._mock_runtime = mock_runtime

    def start_asset(
        self,
        binding_id: str,
        asset: AssetDefinition,
    ) -> AssetRuntimeRecord:
        """Start with Docker when supported, otherwise return a mock record."""
        if self._docker_runtime.supports(asset):
            try:
                return self._docker_runtime.start_asset(binding_id, asset)
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
        return self._mock_runtime.start_asset(binding_id, asset)

    def monitoring_event_for(self, record: AssetRuntimeRecord) -> FalcoEvent:
        """Return a lifecycle event for either Docker or mock records."""
        return _monitoring_event_for_record(record, lifecycle="started")

    def stop_binding_assets(self, binding_id: str) -> list[AssetRuntimeRecord]:
        """Stop Docker-backed records and then stop any remaining mock records."""
        stopped = self._docker_runtime.stop_binding_assets(binding_id)
        stopped.extend(self._mock_runtime.stop_binding_assets(binding_id))
        deduped: dict[str, AssetRuntimeRecord] = {record.runtime_id: record for record in stopped}
        return list(deduped.values())

    def list_accessible_asset_ids(self, binding_id: str) -> list[str]:
        """Return the union of currently reachable Docker and mock assets."""
        asset_ids = self._docker_runtime.list_accessible_asset_ids(binding_id)
        asset_ids.extend(self._mock_runtime.list_accessible_asset_ids(binding_id))
        return list(dict.fromkeys(asset_ids))

    def list_failed_asset_ids(self, binding_id: str) -> list[str]:
        """Return the union of failed Docker and mock assets."""
        asset_ids = self._docker_runtime.list_failed_asset_ids(binding_id)
        asset_ids.extend(self._mock_runtime.list_failed_asset_ids(binding_id))
        return list(dict.fromkeys(asset_ids))


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


def _find_free_port() -> int:
    """Ask the OS for a currently free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _resolve_host_port(requested_host_port: object) -> int:
    """Use the requested port when available, otherwise fall back to a free one."""
    if isinstance(requested_host_port, int) and _port_is_free(requested_host_port):
        return requested_host_port
    return _find_free_port()


def _resolve_port_mappings(runtime: dict[str, object]) -> list[dict[str, int | str]]:
    """Normalize old and new catalog port formats into Docker `-p` records."""
    raw_mappings = runtime.get("port_mappings")
    if isinstance(raw_mappings, list):
        mappings = raw_mappings
    else:
        mappings = [
            {
                "host": "127.0.0.1",
                "requested_host_port": runtime.get("requested_host_port"),
                "container_port": runtime.get("container_port", 80),
            }
        ]

    resolved: list[dict[str, int | str]] = []
    for item in mappings:
        if not isinstance(item, dict):
            continue
        container_port = int(item.get("container_port", 80))
        host_port = _resolve_host_port(item.get("requested_host_port"))
        resolved.append(
            {
                "host": str(item.get("host", "127.0.0.1")),
                "host_port": host_port,
                "container_port": container_port,
            }
        )
    return resolved


def _port_is_free(port: int) -> bool:
    """Return True when localhost:port can be bound right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


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
    healthcheck = runtime.get("healthcheck")
    if not isinstance(healthcheck, dict):
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
