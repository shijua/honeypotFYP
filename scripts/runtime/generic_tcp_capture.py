#!/usr/bin/env python3
"""Run a tiny TCP capture backend for generic probe and payload events.

Honeytrap's packaged runtime is NFQUEUE-oriented, which does not behave like a
normal TCP listener behind the asset-gateway proxy. This helper provides the
gateway-facing listener while emitting JSONL compatible with the existing
high-interaction forwarder and Sigma mapper.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Connection: close\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 21\r\n"
    b"\r\n"
    b"generic capture node\n"
)


class JsonlWriter:
    """Thread-safe JSONL writer shared by connection handler threads."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.touch(exist_ok=True)
        self._path.chmod(0o666)

    def write(self, event: dict[str, object]) -> None:
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                json.dump(event, handle, sort_keys=True)
                handle.write("\n")


def handle_client(
    client: socket.socket,
    address: tuple[str, int],
    *,
    writer: JsonlWriter,
    asset_id: str,
    service: str,
    read_bytes: int,
    banner: bytes,
) -> None:
    """Capture one TCP interaction and write a normalized event."""
    payload = b""
    local_host = ""
    local_port = 0
    try:
        client.settimeout(2.0)
        local_host, local_port = client.getsockname()[:2]
        try:
            payload = client.recv(read_bytes)
        except TimeoutError:
            payload = b""
        if banner:
            client.sendall(banner)
    finally:
        client.close()

    decoded = payload[:read_bytes].decode("utf-8", errors="replace")
    event_type = "payload.transfer" if payload else "connection.open"
    writer.write(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": "honeytrap",
            "asset_id": asset_id,
            "service": service,
            "event_type": event_type,
            "gateway_src_ip": address[0],
            "gateway_src_port": address[1],
            "dst_host": local_host,
            "dst_port": local_port,
            "message": decoded or "connection opened",
            "payload_size": len(payload),
        }
    )


def serve(
    *,
    host: str,
    port: int,
    log_file: Path,
    asset_id: str,
    service: str,
    read_bytes: int,
    banner: bytes,
) -> None:
    """Listen forever and spawn a lightweight thread per connection."""
    writer = JsonlWriter(log_file)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(128)
        while True:
            client, address = server.accept()
            thread = threading.Thread(
                target=handle_client,
                kwargs={
                    "client": client,
                    "address": address,
                    "writer": writer,
                    "asset_id": asset_id,
                    "service": service,
                    "read_bytes": read_bytes,
                    "banner": banner,
                },
                daemon=True,
            )
            thread.start()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a generic TCP capture backend.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("--asset-id", default="honeytrap-generic")
    parser.add_argument("--service", default="tcp")
    parser.add_argument("--read-bytes", type=int, default=4096)
    parser.add_argument("--banner", default=DEFAULT_BANNER.decode("utf-8"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    serve(
        host=args.host,
        port=args.port,
        log_file=args.log_file,
        asset_id=args.asset_id,
        service=args.service,
        read_bytes=args.read_bytes,
        banner=args.banner.encode("utf-8"),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
