from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import validate_asset_telemetry


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


def test_validate_asset_telemetry_filters_requested_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog_path = tmp_path / "catalog.json"
    state_dir = tmp_path / "runtime"
    state_dir.mkdir()
    _write_json(
        catalog_path,
        [
            {"asset_id": "internal-portal", "default_settings": {"runtime": {"backend": "docker"}}},
            {"asset_id": "log4shell-app", "default_settings": {"runtime": {"backend": "compose"}}},
        ],
    )
    monkeypatch.setattr(validate_asset_telemetry, "summarize_demo", lambda _state_dir: {"attackers": []})

    report = validate_asset_telemetry.build_report(
        catalog_path=catalog_path,
        state_dir=state_dir,
        asset_ids={"log4shell-app"},
    )

    assert [item["asset_id"] for item in report["assets"]] == ["log4shell-app"]
    assert report["ok"] is False
