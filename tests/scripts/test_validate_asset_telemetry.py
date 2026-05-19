from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validation import asset_telemetry as validate_asset_telemetry


pytestmark = pytest.mark.unit


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_validate_asset_telemetry_reports_observed_docker_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_path = tmp_path / "catalog.json"
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        catalog_path,
        [
            {
                "asset_id": "internal-portal",
                "telemetry_source": "asset_runtime",
                "default_settings": {
                    "runtime": {
                        "backend": "docker",
                    }
                },
            }
        ],
    )
    _write_json(
        state_dir / "bindings.json",
        {
            "records": [
                {
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "status": "active",
                    "last_seen_ts": "2026-01-01T00:00:00Z",
                }
            ]
        },
    )
    _write_json(
        state_dir / "asset_runtime.json",
        {
            "records": [
                {
                    "binding_id": "binding-1",
                    "asset_id": "internal-portal",
                    "asset_name": "Internal Portal",
                    "status": "running",
                    "template_family": "web-honeypot",
                    "settings": {
                        "runtime_backend": "docker",
                        "container_name": "honeynet-bind-internal-portal",
                    },
                }
            ]
        },
    )
    _write_json(
        state_dir / "gateway_routes.json",
        {
            "routes": [
                {
                    "binding_id": "binding-1",
                    "exposed_assets": ["internal-portal"],
                    "failed_assets": [],
                }
            ]
        },
    )
    _write_json(
        state_dir / "asset_gateway_routes.json",
        {
            "routes": [
                {
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "asset_id": "internal-portal",
                    "public_port": 18080,
                }
            ]
        },
    )
    (state_dir / "internal_http_events.jsonl").write_text(
        '{"asset_id":"internal-portal","path":"/","attacker_key":"198.51.100.10"}\n',
        encoding="utf-8",
    )
    _write_json(state_dir / "opencanary_observations.json", {"observations": []})
    _write_json(state_dir / "profiles.json", {"profiles": {}})
    _write_json(state_dir / "cowrie_observations.json", {"observations": []})
    _write_json(state_dir / "decision_trace.json", {"records": []})
    monkeypatch.setattr(
        validate_asset_telemetry,
        "summarize_demo",
        lambda _state_dir: {
            "attackers": [
                {
                    "current_running_assets": [{"asset_id": "internal-portal"}],
                    "failed_assets": [],
                }
            ]
        },
    )

    report = validate_asset_telemetry.build_report(
        catalog_path=catalog_path,
        state_dir=state_dir,
        asset_ids=set(),
    )

    assert report["ok"] is True
    assert report["assets"][0]["asset_id"] == "internal-portal"
    assert report["assets"][0]["runtime_backend"] == "docker"
    assert report["assets"][0]["telemetry"]["kind"] == "internal_http"


def test_validate_asset_telemetry_accepts_opencanary_asset_with_route_and_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_path = tmp_path / "catalog.json"
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        catalog_path,
        [
            {
                "asset_id": "redis-cache",
                "telemetry_source": "opencanary",
                "default_settings": {
                    "runtime": {
                        "backend": "docker",
                    },
                    "telemetry_validation": {
                        "kind": "opencanary",
                        "service": "redis",
                        "expected_trigger": "redis protocol probe",
                    },
                },
            }
        ],
    )
    _write_json(
        state_dir / "asset_runtime.json",
        {
            "records": [
                {
                    "binding_id": "binding-1",
                    "asset_id": "redis-cache",
                    "asset_name": "Redis Cache",
                    "status": "running",
                    "settings": {"runtime_backend": "docker"},
                }
            ]
        },
    )
    _write_json(
        state_dir / "asset_gateway_routes.json",
        {
            "routes": [
                {
                    "binding_id": "binding-1",
                    "attacker_key": "198.51.100.10",
                    "asset_id": "redis-cache",
                    "public_port": 16379,
                }
            ]
        },
    )
    _write_json(
        state_dir / "opencanary_observations.json",
        {
            "observations": [
                {
                    "attacker_key": "198.51.100.10",
                    "binding_id": "binding-1",
                    "service": "redis",
                }
            ]
        },
    )
    monkeypatch.setattr(
        validate_asset_telemetry,
        "summarize_demo",
        lambda _state_dir: {
            "attackers": [
                {
                    "current_running_assets": [{"asset_id": "redis-cache"}],
                    "failed_assets": [],
                }
            ]
        },
    )

    report = validate_asset_telemetry.build_report(
        catalog_path=catalog_path,
        state_dir=state_dir,
        asset_ids=set(),
    )

    assert report["ok"] is True
    assert report["assets"][0]["telemetry"]["service"] == "redis"


def test_validate_asset_telemetry_requires_cowrie_asset_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_path = tmp_path / "catalog.json"
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        catalog_path,
        [
            {
                "asset_id": "admin-jumpbox",
                "telemetry_source": "cowrie",
                "default_settings": {
                    "runtime": {"backend": "docker"},
                    "telemetry_validation": {
                        "kind": "cowrie",
                        "match": "asset_id",
                        "expected_trigger": "cowrie command",
                    },
                },
            }
        ],
    )
    _write_json(
        state_dir / "asset_runtime.json",
        {"records": [{"asset_id": "admin-jumpbox"}]},
    )
    _write_json(
        state_dir / "asset_gateway_routes.json",
        {"routes": [{"asset_id": "admin-jumpbox"}]},
    )
    _write_json(
        state_dir / "cowrie_observations.json",
        {"observations": [{"eventid": "cowrie.command.input", "command": "id"}]},
    )
    monkeypatch.setattr(
        validate_asset_telemetry,
        "summarize_demo",
        lambda _state_dir: {
            "attackers": [{"current_running_assets": [{"asset_id": "admin-jumpbox"}]}]
        },
    )

    report = validate_asset_telemetry.build_report(
        catalog_path=catalog_path,
        state_dir=state_dir,
        asset_ids=set(),
    )

    assert report["ok"] is False
    assert report["assets"][0]["telemetry"]["count"] == 0


def test_validate_asset_telemetry_requires_high_interaction_asset_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_path = tmp_path / "catalog.json"
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        catalog_path,
        [
            {
                "asset_id": "conpot-plc",
                "telemetry_source": "high_interaction",
                "default_settings": {
                    "runtime": {"backend": "docker"},
                    "telemetry_validation": {
                        "kind": "high_interaction",
                        "source": "conpot",
                        "match": "asset_id",
                        "expected_trigger": "conpot probe",
                    },
                },
            }
        ],
    )
    _write_json(
        state_dir / "asset_runtime.json",
        {"records": [{"asset_id": "conpot-plc"}]},
    )
    _write_json(
        state_dir / "asset_gateway_routes.json",
        {"routes": [{"asset_id": "conpot-plc"}]},
    )
    _write_json(
        state_dir / "high_interaction_observations.json",
        {"observations": [{"source": "conpot", "service": "modbus"}]},
    )
    monkeypatch.setattr(
        validate_asset_telemetry,
        "summarize_demo",
        lambda _state_dir: {
            "attackers": [{"current_running_assets": [{"asset_id": "conpot-plc"}]}]
        },
    )

    report = validate_asset_telemetry.build_report(
        catalog_path=catalog_path,
        state_dir=state_dir,
        asset_ids=set(),
    )

    assert report["ok"] is False
    assert report["assets"][0]["telemetry"]["observation_count"] == 0
