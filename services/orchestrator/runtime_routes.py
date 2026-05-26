"""Port mapping and asset-gateway route helpers for template runtimes.

Template runtimes need two related but separate port concepts:

- local Docker port publishing, used for standalone runtime containers
- asset-gateway routes, used for per-attacker fixed ports and same-port upgrades

Keeping this logic here keeps `template_runtime.py` focused on starting and
stopping containers instead of editing route tables.
"""

from __future__ import annotations

import os
from pathlib import Path
import socket

from libs.common.clock import utcnow
from libs.common.json_store import JsonFileStore
from libs.contracts.models import AssetDefinition


def resolve_port_mappings(
    runtime: dict[str, object],
    asset_id: str | None = None,
    *,
    asset_gateway_managed: bool = False,
    backend_host: str = "",
) -> list[dict[str, int | str]]:
    """Normalize old and new catalog port formats into runtime route records.

    Example:
        {"port_mappings": [{"requested_host_port": 18080, "container_port": 80}]}
        -> [{"host": "127.0.0.1", "host_port": 18080, "container_port": 80}]
    """
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
        host_port = (
            _resolve_public_port(item.get("requested_host_port"), container_port, asset_id)
            if asset_gateway_managed
            else _resolve_host_port(item.get("requested_host_port"), asset_id)
        )
        port_record: dict[str, int | str] = {
            "host": _resolve_host_bind(item.get("host", "127.0.0.1")),
            "host_port": host_port,
            "container_port": container_port,
        }
        if asset_gateway_managed:
            port_record["backend_host"] = backend_host
            port_record["backend_port"] = container_port
        resolved.append(port_record)
    return resolved


def asset_gateway_managed(asset: AssetDefinition, runtime: dict[str, object]) -> bool:
    """Return True when an internal asset should use the unified asset gateway.

    Example:
        internal asset with `runtime.port_mappings` and default env -> True.
        external asset or `HONEYPOT_ASSET_GATEWAY_ENABLED=0` -> False.
    """
    raw = os.environ.get("HONEYPOT_ASSET_GATEWAY_ENABLED", "1").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if asset.exposure_type != "internal":
        return False
    raw_mappings = runtime.get("port_mappings")
    if isinstance(raw_mappings, list):
        return bool(raw_mappings)
    return "requested_host_port" in runtime or "container_port" in runtime


def upsert_asset_gateway_routes(
    *,
    binding_id: str,
    attacker_key: str,
    asset: AssetDefinition,
    runtime_settings: dict[str, object],
) -> None:
    """Persist routes consumed by the unified asset data-plane gateway.

    Routes are keyed by binding, asset, and public port. Rewriting the same key
    is what makes same-port upgrades work: a static backend can be replaced by a
    high-interaction backend without opening a new attacker-visible port.
    """
    routes = runtime_settings.get("port_mappings", [])
    if not isinstance(routes, list):
        return

    new_routes: list[dict[str, object]] = []
    protocol = str(asset.protocols[0]) if asset.protocols else "tcp"
    updated_at = utcnow().isoformat()
    for route in routes:
        if not isinstance(route, dict):
            continue
        public_port = route.get("host_port")
        backend_port = route.get("backend_port", route.get("container_port"))
        backend_host = route.get("backend_host")
        backend_ip = runtime_settings.get("backend_ip")
        if not isinstance(public_port, int):
            continue
        if not isinstance(backend_port, int):
            continue
        if not isinstance(backend_host, str) or not backend_host:
            continue
        new_routes.append(
            {
                "schema_version": "v1",
                "attacker_key": attacker_key,
                "binding_id": binding_id,
                "asset_id": asset.asset_id,
                "asset_name": asset.asset_name,
                "protocol": protocol,
                "public_port": public_port,
                "backend_host": backend_host,
                "backend_port": backend_port,
                "backend_ip": backend_ip if isinstance(backend_ip, str) else "",
                "updated_at": updated_at,
            }
        )

    if not new_routes:
        return

    store = JsonFileStore(asset_gateway_routes_path(), default_data={"routes": []})
    store.replace_list_items(
        "routes",
        new_routes,
        ("binding_id", "asset_id", "public_port"),
    )


def asset_gateway_routes_path() -> Path:
    """Return the JSON route table consumed by services.asset_gateway."""
    raw_path = os.environ.get("HONEYPOT_ASSET_GATEWAY_ROUTES_PATH", "").strip()
    if raw_path:
        return Path(raw_path)
    state_dir = Path(os.environ.get("HONEYPOT_STATE_DIR", "data/runtime"))
    return state_dir / "asset_gateway_routes.json"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _resolve_host_port(requested_host_port: object, asset_id: str | None = None) -> int:
    """Choose a local Docker-published port, falling back when requested is busy."""
    env_port = _asset_port_override(asset_id)
    if env_port is not None and _port_is_free(env_port):
        return env_port
    if isinstance(requested_host_port, int) and _port_is_free(requested_host_port):
        return requested_host_port
    return _find_free_port()


def _resolve_public_port(
    requested_host_port: object,
    container_port: int,
    asset_id: str | None,
) -> int:
    """Choose the attacker-visible port for asset-gateway managed routes."""
    env_port = _asset_port_override(asset_id)
    if env_port is not None:
        return env_port
    if isinstance(requested_host_port, int):
        return requested_host_port
    return container_port


def _resolve_host_bind(default_host: object) -> str:
    override = os.environ.get("HONEYPOT_RUNTIME_HOST_BIND", "").strip()
    if override:
        return override
    return str(default_host)


def _asset_port_override(asset_id: str | None) -> int | None:
    """Return `HONEYPOT_ASSET_<ASSET_ID>_PORT` when it is a valid TCP port."""
    if not asset_id:
        return None
    suffix = asset_id.upper().replace("-", "_")
    raw = os.environ.get(f"HONEYPOT_ASSET_{suffix}_PORT", "").strip()
    if not raw:
        return None
    try:
        port = int(raw)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True
