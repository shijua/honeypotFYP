from __future__ import annotations

from pathlib import Path

import pytest

from scripts.validation.cowrie_attack_mappings import (
    load_attack_techniques,
    validate_command_mapping_rules,
)


pytestmark = pytest.mark.unit


def test_command_mapping_rules_validate_against_mitre_fixture() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "mitre_attack_enterprise_mini.json"
    )
    techniques = load_attack_techniques(fixture_path)

    errors = validate_command_mapping_rules(
        Path("data/cowrie/command_mapping_rules.json"),
        techniques,
    )

    assert errors == []
