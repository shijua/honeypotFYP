from __future__ import annotations

import pytest

from services.cowrie.command_mapping import (
    FileCowrieCommandRuleCatalog,
    normalize_command,
)


pytestmark = pytest.mark.unit


def test_normalize_command_extracts_process_name_and_args() -> None:
    command = normalize_command("/usr/bin/cat /etc/passwd")

    assert command is not None
    assert command.process_name == "cat"
    assert command.args == ("/etc/passwd",)
    assert command.command_line == "/usr/bin/cat /etc/passwd"


def test_file_command_rule_catalog_matches_reviewed_rules() -> None:
    catalog = FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json")

    rules = catalog.match("grep password /app/.env")

    assert [rule.name for rule in rules] == ["credential_file_search"]
    assert rules[0].technique_id == "T1552.001"
    assert rules[0].confidence == "high"
    assert rules[0].source_refs


def test_file_command_rule_catalog_returns_no_match_for_generic_command() -> None:
    catalog = FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json")

    rules = catalog.match("echo hello")

    assert rules == ()
