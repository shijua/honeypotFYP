"""TCP data-plane gateway for adaptive internal assets.

There is one asset-gateway process/container, not one gateway container per
asset. That process opens one TCP listener for each configured public port,
for example 18080 for internal-portal and 16379 for redis-cache.

For every new connection the gateway uses:

- the listener port the client connected to
- the client source IP
- the JSON route table written by the orchestrator

to pick the per-attacker backend container and proxy bytes in both directions.
The gateway is intentionally still a generic TCP proxy for backend traffic. For
configured HTTP asset ports only, it also peeks at the first client request so
internal file/config exploration can become profiler evidence before the bytes
are forwarded to the backend.

For SMTP, the server speaks first, so the gateway observes client commands while
they pass through the normal proxy pipe instead of peeking before connection.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from libs.common.clock import utcnow
from libs.common.iterables import dedupe_preserve
from libs.common.json_utils import read_json_object


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


@dataclass(frozen=True)
class ParsedHttpRequest:
    """Minimal HTTP request material observed before proxying to the asset."""

    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body_preview: str | None = None
    body_truncated: bool = False


def load_routes(path: Path) -> list[AssetRoute]:
    """Load the current asset route table from disk.

    The orchestrator updates this file whenever it starts an adaptive internal
    asset for an attacker. Loading on each connection keeps the gateway simple:
    no restart is needed when a new route is added.
    """
    payload = read_json_object(path, {"routes": []})
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

    initial_client_data = b""
    if _should_observe_http(public_port):
        initial_client_data = await _read_initial_client_data(client_reader)
        await _report_internal_http_request(
            initial_client_data,
            route=route,
            client_ip=client_ip,
        )

    try:
        backend_reader, backend_writer = await asyncio.open_connection(
            route.backend_host,
            route.backend_port,
        )
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return

    if initial_client_data:
        backend_writer.write(initial_client_data)
        await backend_writer.drain()

    await asyncio.gather(
        _pipe(
            client_reader,
            backend_writer,
            observe_data=_protocol_observer(route, client_ip),
        ),
        _pipe(backend_reader, client_writer),
    )


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    observe_data: Callable[[bytes], None] | None = None,
) -> None:
    """Copy bytes in one direction until either side closes the connection."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            if observe_data is not None:
                observe_data(data)
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


async def _read_initial_client_data(
    client_reader: asyncio.StreamReader,
) -> bytes:
    """Peek at the first client bytes for HTTP-only asset ports.

    Non-HTTP ports are never read here because some protocols, such as SSH,
    expect the server banner first. For HTTP assets, clients send the request
    first, so a short read lets the gateway observe the path without changing
    backend behavior.
    """
    timeout = float(os.environ.get("HONEYPOT_ASSET_GATEWAY_HTTP_PEEK_TIMEOUT", "0.5"))
    try:
        return await asyncio.wait_for(client_reader.read(65536), timeout=timeout)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return b""


async def _report_internal_http_request(
    initial_data: bytes,
    *,
    route: AssetRoute,
    client_ip: str,
) -> None:
    """Write an observed internal HTTP request for the control-plane forwarder."""
    parsed = _parse_http_request(initial_data)
    if parsed is None:
        return
    events_file = _internal_http_events_path()
    payload: dict[str, object] = {
        "attacker_key": client_ip,
        "method": parsed.method,
        "path": parsed.path,
        "query_string": parsed.query_string,
        "headers": parsed.headers,
        "body_preview": parsed.body_preview,
        "body_truncated": parsed.body_truncated,
        "protocol": "http",
        "surface": "internal",
        "asset_id": route.asset_id,
    }
    _append_jsonl(events_file, payload)


def _append_jsonl(path: Path, payload: dict[str, object]) -> None:
    """Append one internal HTTP observation without touching control services."""
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line)


def _internal_http_events_path() -> Path:
    raw_path = os.environ.get("HONEYPOT_INTERNAL_HTTP_EVENTS_FILE", "").strip()
    if raw_path:
        return Path(raw_path)
    state_dir = Path(os.environ.get("HONEYPOT_STATE_DIR", "data/runtime"))
    return state_dir / "internal_http_events.jsonl"


def _internal_protocol_events_path() -> Path:
    raw_path = os.environ.get("HONEYPOT_INTERNAL_PROTOCOL_EVENTS_FILE", "").strip()
    if raw_path:
        return Path(raw_path)
    state_dir = Path(os.environ.get("HONEYPOT_STATE_DIR", "data/runtime"))
    return state_dir / "internal_protocol_events.jsonl"


def _protocol_observer(
    route: AssetRoute,
    client_ip: str,
) -> Callable[[bytes], None] | None:
    """Return a client-to-backend observer for protocols the gateway can parse."""
    if route.asset_id == "mail-relay" or route.public_port == 2525:
        return lambda data: _report_smtp_commands(data, route=route, client_ip=client_ip)
    return None


def _report_smtp_commands(
    data: bytes,
    *,
    route: AssetRoute,
    client_ip: str,
) -> None:
    """Write SMTP client commands as OpenCanary-shaped protocol events."""
    commands = _parse_smtp_commands(data)
    if not commands:
        return
    logdata: dict[str, object] = {
        "SERVICE": "smtp",
        "ASSET_ID": route.asset_id,
        "COMMANDS": commands,
        "ASSET_GATEWAY_PUBLIC_PORT": route.public_port,
        "ASSET_GATEWAY_BACKEND_HOST": route.backend_host,
    }
    if "AUTH" in commands:
        # The adapter only needs to know that credential material was attempted.
        logdata["PASSWORD"] = "[redacted]"

    event = {
        "src_host": client_ip,
        "dst_host": route.backend_host,
        "dst_port": route.backend_port,
        "utc_time": utcnow().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "logtype": 25001,
        "node_id": f"asset-gateway-{route.asset_id}",
        "logdata": logdata,
    }
    _append_jsonl(_internal_protocol_events_path(), event)


def _parse_smtp_commands(data: bytes) -> list[str]:
    """Extract SMTP command verbs from client data without storing arguments."""
    text = data.decode("iso-8859-1", errors="ignore")
    commands: list[str] = []
    valid_commands = {
        "AUTH",
        "DATA",
        "EHLO",
        "EXPN",
        "HELO",
        "MAIL",
        "NOOP",
        "QUIT",
        "RCPT",
        "RSET",
        "VRFY",
    }
    for raw_line in text.replace("\r", "\n").split("\n"):
        parts = raw_line.strip().split()
        if not parts:
            continue
        command = parts[0].upper()
        if command in valid_commands:
            commands.append(command)
    return dedupe_preserve(commands)


def _parse_http_request(data: bytes) -> ParsedHttpRequest | None:
    """Parse a best-effort HTTP/1 request from the first client data chunk."""
    if not data:
        return None
    try:
        text = data.decode("iso-8859-1")
    except UnicodeDecodeError:
        return None
    header_text, _, body = text.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 2:
        return None
    method, target = parts[0].upper(), parts[1]
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
        return None
    parsed_target = urlsplit(target)
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    body_preview = body[:4096] if body else None
    return ParsedHttpRequest(
        method=method,
        path=parsed_target.path or "/",
        query_string=parsed_target.query,
        headers=headers,
        body_preview=body_preview,
        body_truncated=len(body) > 4096,
    )


def _should_observe_http(public_port: int) -> bool:
    raw_ports = os.environ.get(
        "HONEYPOT_ASSET_GATEWAY_HTTP_PORTS",
        "18080,18081,18082,18084,18443,18085",
    )
    return public_port in set(_parse_ports(raw_ports))


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
    return dedupe_preserve(ports)


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
