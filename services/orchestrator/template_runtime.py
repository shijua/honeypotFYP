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
    - `web-honeypot` templates with `default_settings.runtime.backend=docker`

    Any unsupported asset should be handled by a higher-level fallback runtime.
    """

    def __init__(
        self,
        repository: TemplateRuntimeRepository,
        generated_dir: str | Path,
        template_root: str | Path = "deploy/templates",
    ) -> None:
        self._repository = repository
        self._generated_dir = Path(generated_dir)
        self._template_root = Path(template_root)

    def supports(self, asset: AssetDefinition) -> bool:
        runtime = asset.default_settings.get("runtime", {})
        return (
            isinstance(runtime, dict)
            and runtime.get("backend") == "docker"
            and asset.template_family == "web-honeypot"
        )

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
        image = str(runtime.get("image", "nginx:alpine"))
        container_port = int(runtime.get("container_port", 80))
        requested_host_port = runtime.get("requested_host_port")
        host_port = _resolve_host_port(requested_host_port)
        container_name = _container_name(binding_id, asset.asset_id)
        web_root = self._prepare_web_root(binding_id, asset)
        health_path = str(runtime.get("health_path", "/"))

        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-d",
                "--name",
                container_name,
                "-p",
                f"127.0.0.1:{host_port}:{container_port}",
                "-v",
                f"{web_root}:/usr/share/nginx/html:ro",
                image,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        settings = dict(asset.default_settings)
        settings.update(
            {
                "runtime_backend": "docker",
                "container_name": container_name,
                "image": image,
                "host_port": host_port,
                "container_port": container_port,
                "health_url": f"http://127.0.0.1:{host_port}{health_path}",
                "generated_dir": str(web_root),
            }
        )
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

    def _prepare_web_root(
        self,
        binding_id: str,
        asset: AssetDefinition,
    ) -> Path:
        """Render a tiny static site from an external template file."""
        web_root = self._generated_dir / binding_id / asset.asset_id
        web_root.mkdir(parents=True, exist_ok=True)
        title = str(asset.default_settings.get("http_title", asset.asset_name))
        description = asset.description or asset.asset_name
        route_path = str(asset.default_settings.get("route_path", "/"))
        template_path = self._template_root / "web" / "default" / "index.html.tpl"
        template = template_path.read_text(encoding="utf-8")
        index_html = template.format(
            title=title,
            description=description,
            route_path=route_path,
        )
        (web_root / "index.html").write_text(index_html, encoding="utf-8")
        return web_root

    def _existing_record(
        self,
        binding_id: str,
        asset_id: str,
    ) -> AssetRuntimeRecord | None:
        for record in self._repository.list_by_binding(binding_id):
            if record.asset_id == asset_id and record.status == "running":
                return record
        return None


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
                # Keep the controller->orchestrator loop resilient even when a
                # local Docker pull/start fails on a developer machine.
                record = self._mock_runtime.start_asset(binding_id, asset)
                updated = record.model_copy(
                    update={
                        "settings": {
                            **record.settings,
                            "runtime_backend": "mock",
                            "runtime_fallback_error": str(exc),
                        }
                    }
                )
                self._mock_runtime.upsert_record(updated)
                return updated
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


def _port_is_free(port: int) -> bool:
    """Return True when localhost:port can be bound right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True
