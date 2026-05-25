from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.evaluation.charts import write_reveal_port_chart
from scripts.evaluation.reveal_port_simulation import (
    ControlPlaneClient,
    evaluate_reveal_port_scenario,
    evaluate_reveal_ports,
    latest_route_for_attacker_port,
    matching_expected_routes,
    validate_scenarios,
)


pytestmark = pytest.mark.unit


def _catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            [
                {
                    "asset_id": "internal-portal",
                    "asset_name": "Internal Portal",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                    "default_settings": {
                        "selection_profile": {
                            "asset_group": "portal",
                            "covered_techniques": ["T1046"],
                            "telemetry_value": 0.6,
                        }
                    },
                },
                {
                    "asset_id": "finance-share",
                    "asset_name": "Finance Share",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Collection"],
                    "dependencies": ["internal-portal"],
                    "default_settings": {
                        "unlock_signals": {"any_http_indicators": ["path:.bak"]},
                        "selection_profile": {
                            "asset_group": "data-share",
                            "covered_techniques": ["T1213"],
                            "telemetry_value": 0.9,
                        },
                    },
                },
            ]
        ),
        encoding="utf-8",
    )


def _prior(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "method": "attack_group_technique_collaborative_filtering",
                "groups": [
                    {
                        "group_id": "G0001",
                        "name": "Fixture Group",
                        "techniques": ["T1213", "T1552.001"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _scenario() -> dict[str, Any]:
    return {
        "scenario_id": "finance",
        "attacker_key": "198.51.100.10",
        "initial_unlocked_assets": ["internal-portal"],
        "profile": {
            "conf_by_technique": {"T1213": 0.95},
            "recent_techniques": ["T1213"],
            "recent_public_http_indicators": ["path:.bak"],
            "recent_evidence_ids": ["e1"],
        },
        "expected_assets": ["finance-share"],
        "expected_routes": [{"asset_id": "finance-share", "public_port": 18082}],
        "forbidden_assets": ["web-admin-console"],
    }


def test_validate_scenarios_requires_expected_routes() -> None:
    with pytest.raises(ValueError, match="missing expected_routes"):
        validate_scenarios(
            [
                {
                    "scenario_id": "bad",
                    "profile": {"recent_evidence_ids": ["e1"]},
                    "expected_assets": ["internal-portal"],
                }
            ]
        )


def test_controller_only_detects_expected_asset(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    prior = tmp_path / "prior.json"
    _catalog(catalog)
    _prior(prior)

    row = evaluate_reveal_port_scenario(
        _scenario(),
        mode="controller-only",
        catalog_path=catalog,
        prior_path=prior,
        route_path=tmp_path / "routes.json",
        control_client=FakeControlPlaneClient(tmp_path / "routes.json"),
    )

    assert row["ok"] is True
    assert row["selected_assets"] == ["finance-share"]


def test_controller_only_fails_forbidden_asset(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    prior = tmp_path / "prior.json"
    _catalog(catalog)
    _prior(prior)

    row = evaluate_reveal_port_scenario(
        {**_scenario(), "forbidden_assets": ["finance-share"]},
        mode="controller-only",
        catalog_path=catalog,
        prior_path=prior,
        route_path=tmp_path / "routes.json",
        control_client=FakeControlPlaneClient(tmp_path / "routes.json"),
    )

    assert row["ok"] is False
    assert row["failure_reason"] == "selected forbidden asset finance-share"


def test_route_matcher_requires_exact_attacker_asset_and_port() -> None:
    routes = [
        {"attacker_key": "198.51.100.10", "asset_id": "finance-share", "public_port": 18082, "updated_at": "2026-01-01T00:00:00Z"},
        {"attacker_key": "198.51.100.11", "asset_id": "finance-share", "public_port": 18082, "updated_at": "2026-01-01T00:00:01Z"},
    ]

    assert matching_expected_routes(
        routes,
        attacker_key="198.51.100.10",
        expected_routes=[{"asset_id": "finance-share", "public_port": 18082}],
    ) == [
        {
            "attacker_key": "198.51.100.10",
            "asset_id": "finance-share",
            "public_port": 18082,
            "updated_at": "2026-01-01T00:00:00Z",
        }
    ]
    assert matching_expected_routes(
        routes,
        attacker_key="198.51.100.10",
        expected_routes=[{"asset_id": "finance-share", "public_port": 18083}],
    ) == []


def test_latest_route_for_same_port_models_same_port_upgrade() -> None:
    routes = [
        {"attacker_key": "198.51.100.10", "asset_id": "malware-sink", "public_port": 18085, "updated_at": "2026-01-01T00:00:00Z"},
        {"attacker_key": "198.51.100.10", "asset_id": "dionaea-capture", "public_port": 18085, "updated_at": "2026-01-01T00:01:00Z"},
    ]

    route = latest_route_for_attacker_port(routes, attacker_key="198.51.100.10", public_port=18085)

    assert route is not None
    assert route["asset_id"] == "dionaea-capture"


def test_live_apply_with_fake_control_client_checks_route_file(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    prior = tmp_path / "prior.json"
    routes = tmp_path / "routes.json"
    _catalog(catalog)
    _prior(prior)
    routes.write_text('{"routes": []}\n', encoding="utf-8")

    row = evaluate_reveal_port_scenario(
        _scenario(),
        mode="live-apply",
        catalog_path=catalog,
        prior_path=prior,
        route_path=routes,
        control_client=FakeControlPlaneClient(routes),
    )

    assert row["ok"] is True
    assert row["actual_routes"][0]["asset_id"] == "finance-share"
    assert row["actual_routes"][0]["public_port"] == 18082


def test_report_fails_when_expected_route_is_missing(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    prior = tmp_path / "prior.json"
    scenarios = tmp_path / "scenarios.jsonl"
    routes = tmp_path / "routes.json"
    _catalog(catalog)
    _prior(prior)
    routes.write_text('{"routes": []}\n', encoding="utf-8")
    scenarios.write_text(json.dumps({**_scenario(), "expected_routes": [{"asset_id": "finance-share", "public_port": 18083}]}) + "\n", encoding="utf-8")

    report = evaluate_reveal_ports(
        mode="live-apply",
        scenario_file=scenarios,
        catalog_path=catalog,
        prior_path=prior,
        route_path=routes,
        control_client=FakeControlPlaneClient(routes),
    )

    assert report["ok"] is False
    assert report["summary"]["failed"] == 1
    assert report["scenarios"][0]["failure_reason"] == "missing route finance-share:18083"

    chart_path = tmp_path / "ports.svg"
    write_reveal_port_chart(report, chart_path)
    assert "Reveal Port Simulation" in chart_path.read_text(encoding="utf-8")


class FakeControlPlaneClient(ControlPlaneClient):
    def __init__(self, route_path: Path) -> None:
        self._route_path = route_path
        self._binding = {
            "binding_id": "binding-test",
            "attacker_key": "198.51.100.10",
            "unlocked_assets": [],
        }

    def post_json(self, host: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        if host.startswith("binding-service"):
            self._binding["attacker_key"] = payload["attacker_key"]
            return dict(self._binding)
        if host.startswith("controller"):
            return {
                "binding_id": self._binding["binding_id"],
                "actions": [
                    {
                        "action_type": "unlock",
                        "binding_id": self._binding["binding_id"],
                        "asset_id": "finance-share",
                        "reason": "fake controller",
                    }
                ],
                "decision_events": [{"details": {"selected_strategy": "exploit", "selected_technique": "T1213"}}],
                "candidate_asset_ids": ["finance-share"],
            }
        if host.startswith("orchestrator"):
            for action in payload.get("actions", []):
                asset_id = action.get("asset_id")
                if isinstance(asset_id, str) and asset_id not in self._binding["unlocked_assets"]:
                    self._binding["unlocked_assets"].append(asset_id)
                    self._append_route(asset_id)
            return {"binding": dict(self._binding), "runtime_events": [], "route_updates": []}
        raise AssertionError(f"unexpected POST {host}{path}")

    def get_json(self, host: str, path: str) -> dict[str, Any]:
        if host.startswith("gateway"):
            return {"binding_id": self._binding["binding_id"], "exposed_assets": list(self._binding["unlocked_assets"])}
        raise AssertionError(f"unexpected GET {host}{path}")

    def _append_route(self, asset_id: str) -> None:
        port_by_asset = {"finance-share": 18082, "internal-portal": 18080}
        payload = json.loads(self._route_path.read_text(encoding="utf-8"))
        payload.setdefault("routes", []).append(
            {
                "attacker_key": self._binding["attacker_key"],
                "binding_id": self._binding["binding_id"],
                "asset_id": asset_id,
                "public_port": port_by_asset.get(asset_id, 0),
                "backend_host": f"fake-{asset_id}",
                "backend_port": 80,
                "updated_at": "2026-01-01T00:00:00Z",
            }
        )
        self._route_path.write_text(json.dumps(payload), encoding="utf-8")
