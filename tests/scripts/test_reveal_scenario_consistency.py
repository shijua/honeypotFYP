from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from services.controller.repository import FileAssetRepository
from scripts.evaluation.reveal_policy import load_scenarios


ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.unit


def test_reveal_policy_scenarios_reference_existing_assets_and_covered_techniques() -> None:
    assets = _assets_by_id()
    scenarios = load_scenarios(ROOT / "tests/fixtures/reveal_policy_scenarios.jsonl")

    assert {item.get("scenario_type") for item in scenarios} == {
        "fit",
        "boundary",
        "scanner-like",
        "mixed-signal",
        "false-positive-reveal",
    }

    for scenario in scenarios:
        expected_assets = _strings(scenario.get("expected_reasonable_assets"))
        hidden_assets = _strings(scenario.get("expected_hidden_assets"))
        for asset_id in [*expected_assets, *hidden_assets, *_strings(scenario.get("useful_followup_assets"))]:
            assert asset_id in assets, f"{scenario['scenario_id']} references unknown asset {asset_id}"

        if scenario.get("expected_no_reveal") or scenario.get("boundary"):
            continue
        assert _expected_assets_cover_scenario_technique(scenario, expected_assets, assets), scenario["scenario_id"]


def test_reveal_port_scenarios_reference_existing_assets_routes_and_covered_techniques() -> None:
    assets = _assets_by_id()
    scenarios = load_scenarios(ROOT / "tests/fixtures/reveal_port_scenarios.jsonl")

    for scenario in scenarios:
        expected_assets = _strings(scenario.get("expected_assets"))
        assert expected_assets, scenario["scenario_id"]
        for asset_id in expected_assets:
            assert asset_id in assets, f"{scenario['scenario_id']} references unknown asset {asset_id}"
        for route in scenario.get("expected_routes", []):
            assert route["asset_id"] in assets, f"{scenario['scenario_id']} route references unknown asset {route['asset_id']}"
        assert _expected_assets_cover_scenario_technique(scenario, expected_assets, assets), scenario["scenario_id"]


def _assets_by_id() -> dict[str, Any]:
    return {
        asset.asset_id: asset
        for asset in FileAssetRepository(ROOT / "data/assets/catalog.json").list_all()
    }


def _expected_assets_cover_scenario_technique(
    scenario: dict[str, Any],
    expected_assets: list[str],
    assets: dict[str, Any],
) -> bool:
    scenario_techniques = _scenario_techniques(scenario)
    if not scenario_techniques:
        return True
    covered = set()
    for asset_id in expected_assets:
        profile = assets[asset_id].default_settings.get("selection_profile", {})
        techniques = profile.get("covered_techniques", []) if isinstance(profile, dict) else []
        covered.update(item for item in techniques if isinstance(item, str))
    return any(_same_family(left, right) for left in scenario_techniques for right in covered)


def _scenario_techniques(scenario: dict[str, Any]) -> set[str]:
    profile = scenario.get("profile")
    techniques: set[str] = set()
    if isinstance(profile, dict):
        techniques.update(_strings(profile.get("recent_techniques")))
        conf = profile.get("conf_by_technique")
        if isinstance(conf, dict):
            techniques.update(key for key in conf if isinstance(key, str))
    events = scenario.get("evidence_sequence")
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict):
                techniques.update(_strings([event.get("technique"), event.get("tech_id")]))
    return techniques


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []


def _same_family(left: str, right: str) -> bool:
    return left.split(".", 1)[0] == right.split(".", 1)[0]
