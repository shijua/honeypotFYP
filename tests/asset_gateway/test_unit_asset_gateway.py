from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.asset_gateway.app import (
    AssetRoute,
    _internal_portal_session_result,
    _parse_http_request,
    _parse_smtp_commands,
    _protocol_observer,
    _with_auth_result,
    load_routes,
    select_route,
)


pytestmark = pytest.mark.unit


def test_select_route_prefers_source_ip_exact_match() -> None:
    routes = [
        AssetRoute(
            attacker_key="198.51.100.10",
            binding_id="binding-a",
            asset_id="internal-portal",
            public_port=18080,
            backend_host="honeynet-a-internal-portal",
            backend_port=80,
        ),
        AssetRoute(
            attacker_key="198.51.100.20",
            binding_id="binding-b",
            asset_id="internal-portal",
            public_port=18080,
            backend_host="honeynet-b-internal-portal",
            backend_port=80,
        ),
    ]

    route = select_route(routes, client_ip="198.51.100.20", public_port=18080)

    assert route is not None
    assert route.binding_id == "binding-b"
    assert route.backend_host == "honeynet-b-internal-portal"


def test_select_route_uses_latest_route_for_same_attacker_and_port() -> None:
    routes = [
        AssetRoute(
            attacker_key="198.51.100.10",
            binding_id="binding-a",
            asset_id="malware-sink",
            public_port=18085,
            backend_host="static-malware-sink",
            backend_port=80,
            updated_at="2026-04-27T12:00:00Z",
        ),
        AssetRoute(
            attacker_key="198.51.100.10",
            binding_id="binding-a",
            asset_id="dionaea-capture",
            public_port=18085,
            backend_host="dionaea-capture",
            backend_port=80,
            updated_at="2026-04-27T12:01:00Z",
        ),
    ]

    route = select_route(routes, client_ip="198.51.100.10", public_port=18085)

    assert route is not None
    assert route.asset_id == "dionaea-capture"
    assert route.backend_host == "dionaea-capture"


def test_select_route_rejects_unmatched_source_ip_even_when_port_has_one_route() -> None:
    routes = [
        AssetRoute(
            attacker_key="198.51.100.10",
            binding_id="binding-a",
            asset_id="redis-cache",
            public_port=16379,
            backend_host="honeynet-a-redis-cache",
            backend_port=6379,
        )
    ]

    route = select_route(routes, client_ip="172.18.0.1", public_port=16379)

    assert route is None


def test_load_routes_skips_invalid_route_table_items(tmp_path: Path) -> None:
    route_path = tmp_path / "asset_gateway_routes.json"
    route_path.write_text(
        json.dumps(
            {
                "routes": [
                    {
                        "attacker_key": "198.51.100.10",
                        "binding_id": "binding-a",
                        "asset_id": "git-internal",
                        "public_port": 19418,
                        "backend_host": "honeynet-a-git-internal",
                        "backend_port": 9418,
                    },
                    "not-a-route",
                ]
            }
        ),
        encoding="utf-8",
    )

    routes = load_routes(route_path)

    assert len(routes) == 1
    assert routes[0].asset_id == "git-internal"


def test_parse_http_request_extracts_path_query_and_headers() -> None:
    request = _parse_http_request(
        b"GET /finance/archive/payroll.zip?download=1 HTTP/1.1\r\n"
        b"Host: example.internal\r\n"
        b"User-Agent: curl/8.0\r\n"
        b"\r\n"
    )

    assert request is not None
    assert request.method == "GET"
    assert request.path == "/finance/archive/payroll.zip"
    assert request.query_string == "download=1"
    assert request.headers["user-agent"] == "curl/8.0"


def test_internal_portal_session_accepts_leaked_reader_token() -> None:
    request = _parse_http_request(
        b"POST /session HTTP/1.1\r\n"
        b"Host: intranet.internal\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"username=portal.reader&token=nbp_reader_2026_04_window"
    )
    route = AssetRoute(
        attacker_key="198.51.100.10",
        binding_id="binding-a",
        asset_id="internal-portal",
        public_port=18080,
        backend_host="honeynet-a-internal-portal",
        backend_port=80,
    )

    result = _internal_portal_session_result(request, route=route)

    assert result is not None
    assert result.status_code == 200
    assert result.auth_result == "success"
    assert result.body["role"] == "directory-readonly"
    assert _with_auth_result(request, result.auth_result).body_preview.endswith(
        "auth_result=success"
    )


def test_internal_portal_session_rejects_wrong_token() -> None:
    request = _parse_http_request(
        b"POST /session HTTP/1.1\r\n"
        b"Host: intranet.internal\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"\r\n"
        b"username=portal.reader&token=wrong"
    )
    route = AssetRoute(
        attacker_key="198.51.100.10",
        binding_id="binding-a",
        asset_id="internal-portal",
        public_port=18080,
        backend_host="honeynet-a-internal-portal",
        backend_port=80,
    )

    result = _internal_portal_session_result(request, route=route)

    assert result is not None
    assert result.status_code == 401
    assert result.auth_result == "failure"


def test_parse_smtp_commands_extracts_command_verbs_only() -> None:
    commands = _parse_smtp_commands(
        b"HELO tester\r\nMAIL FROM:<admin@example.test>\r\nRCPT TO:<root@example.test>\r\n"
    )

    assert commands == ["HELO", "MAIL", "RCPT"]


def test_high_interaction_observer_writes_gateway_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    events_file = tmp_path / "high_interaction_events.jsonl"
    monkeypatch.setenv("HONEYPOT_HIGH_INTERACTION_EVENTS_FILE", str(events_file))
    route = AssetRoute(
        attacker_key="198.51.100.10",
        binding_id="binding-a",
        asset_id="dionaea-capture",
        public_port=18085,
        backend_host="dionaea-capture",
        backend_port=80,
    )

    observer = _protocol_observer(route, "198.51.100.10")

    assert observer is not None
    observer(b"GET /downloads/agent-update.bin HTTP/1.1\r\nHost: sink\r\n\r\n")
    event = json.loads(events_file.read_text(encoding="utf-8").strip())
    assert event["source"] == "dionaea"
    assert event["asset_id"] == "dionaea-capture"
    assert event["attacker_key"] == "198.51.100.10"
    assert event["service"] == "http"
    assert "agent-update.bin" in event["message"]
