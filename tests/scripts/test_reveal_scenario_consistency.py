from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from libs.common.attack import same_technique_family
from services.controller.repository import FileAssetRepository
from scripts.evaluation.reveal_policy import load_scenarios


ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.unit


def test_reveal_policy_scenarios_reference_existing_assets_and_covered_techniques() -> None:
    assets = _assets_by_id()
    scenarios = load_scenarios(ROOT / "tests/fixtures/reveal_policy_scenarios.json")

    assert {
        "fit",
        "boundary",
        "scanner-like",
        "mixed-signal",
        "false-positive-reveal",
        "configuration",
        "configuration-negative",
    }.issubset({item.get("scenario_type") for item in scenarios})
    reference_text = (ROOT / "tests/fixtures/README.md").read_text(encoding="utf-8")

    for scenario in scenarios:
        assert isinstance(scenario.get("reference_id"), str) and scenario["reference_id"], scenario["scenario_id"]
        assert scenario["reference_id"] in reference_text, scenario["scenario_id"]
        expected_assets = _strings(scenario.get("expected_reasonable_assets"))
        hidden_assets = _strings(scenario.get("expected_hidden_assets"))
        useful_assets = _strings(scenario.get("useful_followup_assets"))
        diagnostic_assets = _strings(scenario.get("diagnostic_followup_assets"))
        touched_assets = _strings(scenario.get("touched_assets"))
        for asset_id in [*expected_assets, *hidden_assets, *useful_assets, *diagnostic_assets, *touched_assets]:
            assert asset_id in assets, f"{scenario['scenario_id']} references unknown asset {asset_id}"
        allowed_touched = set(expected_assets) | set(useful_assets) | set(diagnostic_assets)
        for asset_id in touched_assets:
            assert asset_id in allowed_touched, f"{scenario['scenario_id']} touches unlinked asset {asset_id}"
        _assert_expected_reveals_are_catalog_backed(scenario, assets)

        if scenario.get("expected_no_reveal") or scenario.get("boundary"):
            continue
        assert _expected_assets_cover_scenario_technique(scenario, expected_assets, assets), scenario["scenario_id"]


def test_reveal_port_scenarios_reference_existing_assets_routes_and_covered_techniques() -> None:
    assets = _assets_by_id()
    scenarios = load_scenarios(ROOT / "tests/fixtures/reveal_port_scenarios.json")

    for scenario in scenarios:
        expected_assets = _strings(scenario.get("expected_assets"))
        assert expected_assets, scenario["scenario_id"]
        for asset_id in expected_assets:
            assert asset_id in assets, f"{scenario['scenario_id']} references unknown asset {asset_id}"
        for route in scenario.get("expected_routes", []):
            assert route["asset_id"] in assets, f"{scenario['scenario_id']} route references unknown asset {route['asset_id']}"
        _assert_expected_actions_are_catalog_backed(scenario, assets)
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
    return any(same_technique_family(left, right) for left in scenario_techniques for right in covered)


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


def _assert_expected_reveals_are_catalog_backed(
    scenario: dict[str, Any],
    assets: dict[str, Any],
) -> None:
    reveals = [
        *_scenario_reveal_list(scenario.get("expected_reveals")),
        *_scenario_reveal_list(scenario.get("allowed_reveals")),
    ]
    for reveal in reveals:
        assert isinstance(reveal, dict), scenario["scenario_id"]
        _assert_expected_action_is_catalog_backed(reveal, scenario, assets)


def _scenario_reveal_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _assert_expected_actions_are_catalog_backed(
    scenario: dict[str, Any],
    assets: dict[str, Any],
) -> None:
    for action in scenario.get("expected_actions", []):
        assert isinstance(action, dict), scenario["scenario_id"]
        _assert_expected_action_is_catalog_backed(action, scenario, assets)


def _assert_expected_action_is_catalog_backed(
    action: dict[str, Any],
    scenario: dict[str, Any],
    assets: dict[str, Any],
) -> None:
    asset_id = action.get("asset_id")
    assert isinstance(asset_id, str) and asset_id in assets, scenario["scenario_id"]
    target_asset_id = action.get("target_asset_id")
    if isinstance(target_asset_id, str):
        assert target_asset_id in assets, scenario["scenario_id"]
    if action.get("action_type") != "configure":
        return
    configuration_id = action.get("configuration_id")
    assert isinstance(configuration_id, str), scenario["scenario_id"]
    variants = assets[asset_id].default_settings.get("configuration_variants", [])
    assert any(
        isinstance(variant, dict)
        and variant.get("configuration_id") == configuration_id
        and (
            target_asset_id is None
            or variant.get("target_asset_id") == target_asset_id
        )
        for variant in variants
    ), scenario["scenario_id"]
