from __future__ import annotations

import json

import pytest

from scripts.summarize_cowrie_commands import (
    load_observations,
    summarize_commands,
    write_report,
)
from services.cowrie.command_mapping import FileCowrieCommandRuleCatalog


pytestmark = pytest.mark.unit


def test_summarize_commands_counts_mapped_and_unmapped_command_inputs() -> None:
    observations = [
        {
            "eventid": "cowrie.command.input",
            "command": "nmap 10.0.0.0/24",
            "attacker_key": "198.51.100.10",
            "session": "s-1",
            "ts": "2026-01-01T00:00:01Z",
        },
        {
            "eventid": "cowrie.command.input",
            "command": "nmap 10.0.0.0/24",
            "attacker_key": "198.51.100.10",
            "session": "s-1",
            "ts": "2026-01-01T00:00:02Z",
        },
        {
            "eventid": "cowrie.command.input",
            "command": "uname -a",
            "attacker_key": "198.51.100.11",
            "session": "s-2",
            "ts": "2026-01-01T00:00:03Z",
        },
        {
            "eventid": "cowrie.command.failed",
            "command": "nmap 10.0.0.0/24",
            "attacker_key": "198.51.100.10",
            "session": "s-1",
            "ts": "2026-01-01T00:00:04Z",
        },
    ]

    report = summarize_commands(
        observations,
        FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json"),
    )

    assert report["total_command_input_events"] == 3
    assert report["unique_commands"] == 2
    assert report["mapped_unique_commands"] == 1
    assert report["unmapped_unique_commands"] == 1
    assert report["commands"][0]["command"] == "nmap 10.0.0.0/24"
    assert report["commands"][0]["count"] == 2
    assert report["commands"][0]["techniques"] == [
        {
            "rule_name": "network_service_discovery",
            "technique_id": "T1046",
            "confidence": "high",
        }
    ]
    assert report["unmapped_commands"][0]["command"] == "uname -a"


def test_load_observations_and_write_report_round_trip(tmp_path) -> None:
    observations_file = tmp_path / "cowrie_observations.json"
    report_file = tmp_path / "cowrie_command_coverage.json"
    observations_file.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "eventid": "cowrie.command.input",
                        "command": "id",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    observations = load_observations(observations_file)
    report = summarize_commands(
        observations,
        FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json"),
    )
    write_report(report, report_file)

    written = json.loads(report_file.read_text(encoding="utf-8"))
    assert written["total_command_input_events"] == 1
    assert written["commands"][0]["command"] == "id"


def test_load_observations_returns_empty_list_for_missing_file(tmp_path) -> None:
    observations = load_observations(tmp_path / "missing.json")

    assert observations == []
