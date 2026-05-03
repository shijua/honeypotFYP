from __future__ import annotations

from pathlib import Path

import pytest

from services.cowrie.command_mapping import (
    CompositeCowrieCommandRuleCatalog,
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


def test_file_command_rule_catalog_preserves_regex_escape_case() -> None:
    catalog = FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json")

    rules = catalog.match("telnet 10.0.0.1 22")

    assert [rule.name for rule in rules] == ["network_service_discovery"]


def test_file_command_rule_catalog_returns_no_match_for_generic_command() -> None:
    catalog = FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json")

    rules = catalog.match("echo hello")

    assert rules == ()


def test_file_command_rule_catalog_honors_exclude_match(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        """{"schema_version":"v1","rules":[{"name":"netcat_connect","technique_id":"T1046","confidence":"medium","match":{"process_names":["nc"]},"exclude_match":{"command_line_contains_any":[" -l "]},"source_refs":[{"type":"test","name":"test"}]}]}""",
        encoding="utf-8",
    )
    catalog = FileCowrieCommandRuleCatalog(rules_file)

    assert [rule.technique_id for rule in catalog.match("nc 10.0.0.5 22")] == ["T1046"]
    assert catalog.match("nc -l 4444") == ()


def test_file_command_rule_catalog_can_load_multiple_files(tmp_path: Path) -> None:
    local_rules = tmp_path / "local.json"
    external_rules = tmp_path / "external.json"
    local_rules.write_text(
        """{"schema_version":"v1","rules":[{"name":"local_id","technique_id":"T1033","confidence":"medium","match":{"process_names":["id"]},"source_refs":[{"type":"local","name":"local"}]}]}""",
        encoding="utf-8",
    )
    external_rules.write_text(
        """{"schema_version":"v1","rules":[{"name":"sigma_download","technique_id":"T1105","confidence":"high","match":{"process_names":["curl"]},"source_refs":[{"type":"sigma_rule","name":"sigma"}]}]}""",
        encoding="utf-8",
    )

    catalog = FileCowrieCommandRuleCatalog((local_rules, external_rules))

    assert [rule.technique_id for rule in catalog.match("id")] == ["T1033"]
    assert [rule.technique_id for rule in catalog.match("curl http://x")] == ["T1105"]


def test_file_command_rule_catalog_dedupes_repeated_rules(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    payload = """{"schema_version":"v1","rules":[{"name":"same","technique_id":"T1033","confidence":"medium","match":{"process_names":["id"]},"source_refs":[{"type":"local","name":"local"}]}]}"""
    first.write_text(payload, encoding="utf-8")
    second.write_text(payload, encoding="utf-8")

    catalog = FileCowrieCommandRuleCatalog((first, second))

    assert len(catalog.match("id")) == 1


def test_composite_command_rule_catalog_combines_catalogs_without_duplicates(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text(
        """{"schema_version":"v1","rules":[{"name":"same","technique_id":"T1033","confidence":"medium","match":{"process_names":["id"]},"source_refs":[{"type":"local","name":"local"}]}]}""",
        encoding="utf-8",
    )
    second.write_text(
        """{"schema_version":"v1","rules":[{"name":"same","technique_id":"T1033","confidence":"medium","match":{"process_names":["id"]},"source_refs":[{"type":"sigma_rule","name":"sigma"}]},{"name":"download","technique_id":"T1105","confidence":"high","match":{"process_names":["curl"]},"source_refs":[{"type":"sigma_rule","name":"sigma"}]}]}""",
        encoding="utf-8",
    )
    catalog = CompositeCowrieCommandRuleCatalog(
        (
            FileCowrieCommandRuleCatalog(first),
            FileCowrieCommandRuleCatalog(second),
        )
    )

    assert [rule.name for rule in catalog.match("id")] == ["same"]
    assert [rule.technique_id for rule in catalog.match("curl http://x")] == ["T1105"]
