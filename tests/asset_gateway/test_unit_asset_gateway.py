from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.asset_gateway.app import AssetRoute, load_routes, select_route


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
