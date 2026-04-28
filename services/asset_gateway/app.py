"""TCP data-plane gateway for adaptive internal assets.

There is one asset-gateway process/container, not one gateway container per
asset. That process opens one TCP listener for each configured public port,
for example 18080 for internal-portal and 16379 for redis-cache.

For every new connection the gateway uses:

- the listener port the client connected to
- the client source IP
- the JSON route table written by the orchestrator

to pick the per-attacker backend container and proxy bytes in both directions.
The gateway does not understand HTTP, Redis, Git, or MySQL; it is intentionally
just a generic TCP proxy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AssetRoute:
    """One source-IP route from a fixed public port to a backend container.

    Example:
        attacker 198.51.100.77 on public port 18080 routes to
        honeynet-abcd1234-internal-portal:80.
    """

    attacker_key: str
    binding_id: str
    asset_id: str
    public_port: int
    backend_host: str
    backend_port: int
    updated_at: str = ""


def load_routes(path: Path) -> list[AssetRoute]:
    """Load the current asset route table from disk.

    The orchestrator updates this file whenever it starts an adaptive internal
    asset for an attacker. Loading on each connection keeps the gateway simple:
    no restart is needed when a new route is added.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    routes = payload.get("routes", []) if isinstance(payload, dict) else []
    if not isinstance(routes, list):
        return []
    return [_route_from_item(item) for item in routes if isinstance(item, dict)]


def select_route(
    routes: list[AssetRoute],
    *,
    client_ip: str,
    public_port: int,
) -> AssetRoute | None:
    """Pick the unlocked backend route for one client IP and fixed public port."""
    port_routes = [route for route in routes if route.public_port == public_port]
    exact_routes = [
        route for route in port_routes if route.attacker_key == client_ip
    ]
    if exact_routes:
        return sorted(exact_routes, key=lambda route: route.updated_at)[-1]
    return None


async def serve_ports(ports: list[int], route_path: Path) -> None:
    """Start one TCP listener per fixed asset gateway port.

    This is the part that can look confusing in compose: one `asset-gateway`
    service listens on many ports. Each port gets its own asyncio server, but
    all servers run inside the same Python process and share the same route
    table.
    """
    servers = [
        await asyncio.start_server(
            lambda reader, writer, port=port: _handle_connection(
                reader,
                writer,
                public_port=port,
                route_path=route_path,
            ),
            host="0.0.0.0",
            port=port,
        )
        for port in ports
    ]
    async with _server_group(servers):
        await asyncio.gather(*(server.serve_forever() for server in servers))


async def _handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    public_port: int,
    route_path: Path,
) -> None:
    """Handle one inbound client connection and proxy it to the selected asset."""
    client_ip = _peer_ip(client_writer)
    route = select_route(
        load_routes(route_path),
        client_ip=client_ip,
        public_port=public_port,
    )
    if route is None:
        # No binding has exposed this asset to this source IP yet.
        client_writer.close()
        await client_writer.wait_closed()
        return

    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            route.backend_host,
            route.backend_port,
        )
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return

    await asyncio.gather(
        _pipe(client_reader, backend_writer),
        _pipe(backend_reader, client_writer),
    )


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Copy bytes in one direction until either side closes the connection."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def _route_from_item(item: dict[str, Any]) -> AssetRoute:
    return AssetRoute(
        attacker_key=str(item.get("attacker_key", "")),
        binding_id=str(item.get("binding_id", "")),
        asset_id=str(item.get("asset_id", "")),
        public_port=int(item.get("public_port", 0) or 0),
        backend_host=str(item.get("backend_host", "")),
        backend_port=int(item.get("backend_port", 0) or 0),
        updated_at=str(item.get("updated_at", "")),
    )


def _peer_ip(writer: asyncio.StreamWriter) -> str:
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    return ""


class _server_group:
    """Small async context manager that closes all listener sockets together."""

    def __init__(self, servers: list[asyncio.AbstractServer]) -> None:
        self._servers = servers

    async def __aenter__(self) -> "_server_group":
        return self

    async def __aexit__(self, *args: object) -> None:
        for server in self._servers:
            server.close()
        await asyncio.gather(
            *(server.wait_closed() for server in self._servers),
            return_exceptions=True,
        )


def _default_route_path() -> Path:
    raw_path = os.environ.get("HONEYPOT_ASSET_GATEWAY_ROUTES_PATH", "").strip()
    if raw_path:
        return Path(raw_path)
    state_dir = Path(os.environ.get("HONEYPOT_STATE_DIR", "data/runtime"))
    return state_dir / "asset_gateway_routes.json"


def _parse_ports(value: str) -> list[int]:
    """Parse comma-separated listen ports and preserve order without duplicates."""
    ports: list[int] = []
    for raw_port in value.split(","):
        raw_port = raw_port.strip()
        if not raw_port:
            continue
        port = int(raw_port)
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port: {port}")
        ports.append(port)
    return list(dict.fromkeys(ports))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the honeynet asset gateway")
    parser.add_argument(
        "--ports",
        default=os.environ.get("HONEYPOT_ASSET_GATEWAY_PORTS", "18080"),
        help="Comma-separated fixed ports to listen on.",
    )
    parser.add_argument(
        "--routes",
        type=Path,
        default=_default_route_path(),
        help="JSON route table written by the orchestrator.",
    )
    args = parser.parse_args()
    asyncio.run(serve_ports(_parse_ports(args.ports), args.routes))


if __name__ == "__main__":
    main()
