from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.asset_gateway import app as asset_gateway_app


pytestmark = pytest.mark.component


@pytest.mark.asyncio
async def test_asset_gateway_proxies_only_when_source_ip_matches_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_path = _write_route_table(
        tmp_path,
        attacker_key="127.0.0.1",
        public_port=18080,
        backend_port=80,
    )
    client_reader = _FakeReader([b"ping", b""])
    client_writer = _FakeWriter()
    backend_reader = _FakeReader([b"pong", b""])
    backend_writer = _FakeWriter()
    opened: list[tuple[str, int]] = []

    async def fake_open_connection(host: str, port: int) -> tuple[_FakeReader, _FakeWriter]:
        opened.append((host, port))
        return backend_reader, backend_writer

    monkeypatch.setattr(asset_gateway_app, "_peer_ip", lambda _writer: "127.0.0.1")
    monkeypatch.setattr(asset_gateway_app.asyncio, "open_connection", fake_open_connection)

    await asset_gateway_app._handle_connection(
        client_reader,
        client_writer,
        public_port=18080,
        route_path=route_path,
    )

    assert opened == [("backend.local", 80)]
    assert backend_writer.written == [b"ping"]
    assert client_writer.written == [b"pong"]


@pytest.mark.asyncio
async def test_asset_gateway_closes_unmatched_source_ip_without_proxying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_path = _write_route_table(
        tmp_path,
        attacker_key="198.51.100.10",
        public_port=18080,
        backend_port=80,
    )
    client_writer = _FakeWriter()

    async def fake_open_connection(_host: str, _port: int) -> tuple[_FakeReader, _FakeWriter]:
        raise AssertionError("unmatched source IP must not open a backend connection")

    monkeypatch.setattr(asset_gateway_app, "_peer_ip", lambda _writer: "127.0.0.1")
    monkeypatch.setattr(asset_gateway_app.asyncio, "open_connection", fake_open_connection)

    await asset_gateway_app._handle_connection(
        _FakeReader([b"ping", b""]),
        client_writer,
        public_port=18080,
        route_path=route_path,
    )

    assert client_writer.closed is True
    assert client_writer.written == []


@pytest.mark.asyncio
async def test_asset_gateway_reports_internal_http_request_before_proxying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route_path = _write_route_table(
        tmp_path,
        attacker_key="127.0.0.1",
        public_port=18082,
        backend_port=80,
        asset_id="finance-share",
    )
    client_reader = _FakeReader(
        [
            b"GET /finance/archive/2024/payroll-archive.zip HTTP/1.1\r\n"
            b"Host: finance.internal\r\n"
            b"User-Agent: curl/8.0\r\n"
            b"\r\n",
            b"",
        ]
    )
    client_writer = _FakeWriter()
    backend_reader = _FakeReader([b"HTTP/1.1 200 OK\r\n\r\n", b""])
    backend_writer = _FakeWriter()
    events_file = tmp_path / "internal_http_events.jsonl"

    async def fake_open_connection(host: str, port: int) -> tuple[_FakeReader, _FakeWriter]:
        return backend_reader, backend_writer

    monkeypatch.setenv(
        "HONEYPOT_INTERNAL_HTTP_EVENTS_FILE",
        str(events_file),
    )
    monkeypatch.setattr(asset_gateway_app, "_peer_ip", lambda _writer: "127.0.0.1")
    monkeypatch.setattr(asset_gateway_app.asyncio, "open_connection", fake_open_connection)

    await asset_gateway_app._handle_connection(
        client_reader,
        client_writer,
        public_port=18082,
        route_path=route_path,
    )

    payload = json.loads(events_file.read_text(encoding="utf-8").strip())
    assert payload["attacker_key"] == "127.0.0.1"
    assert payload["surface"] == "internal"
    assert payload["asset_id"] == "finance-share"
    assert payload["path"] == "/finance/archive/2024/payroll-archive.zip"
    assert backend_writer.written[0].startswith(b"GET /finance/archive")


def _write_route_table(
    tmp_path: Path,
    *,
    attacker_key: str,
    public_port: int,
    backend_port: int,
    asset_id: str = "internal-portal",
) -> Path:
    route_path = tmp_path / "asset_gateway_routes.json"
    route_path.write_text(
        json.dumps(
            {
                "routes": [
                    {
                        "attacker_key": attacker_key,
                        "binding_id": "binding-a",
                        "asset_id": asset_id,
                        "public_port": public_port,
                        "backend_host": "backend.local",
                        "backend_port": backend_port,
                        "updated_at": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return route_path


class _FakeReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def read(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class _FakeWriter:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, _name: str) -> Any:
        return None
