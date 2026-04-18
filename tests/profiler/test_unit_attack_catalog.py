from __future__ import annotations

import pytest

from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def test_mitre_attack_catalog_reads_tactic_relationships_from_stix_fixture() -> None:
    catalog = build_test_attack_catalog()

    assert catalog.tactic_for_technique("T1003") == "Credential Access"
    assert catalog.canonical_tactic_name("command_and_control") == "Command and Control"
    assert catalog.default_technique_for_tactic("Privilege Escalation") == "T1548.003"
