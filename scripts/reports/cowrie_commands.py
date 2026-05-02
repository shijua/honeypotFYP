#!/usr/bin/env python3
"""Summarize Cowrie command coverage against reviewed ATT&CK mapping rules.

The local Cowrie lab stores sanitized observations in
`data/runtime/cowrie_observations.json`. This script reads those observations,
counts `cowrie.command.input` commands, and reports whether each command
currently matches `data/cowrie/command_mapping_rules.json`.

Example:
    .venv/bin/python scripts/reports/cowrie_commands.py \
      --write-report data/runtime/cowrie_command_coverage.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Protocol

from services.cowrie.command_mapping import (
    CowrieCommandRule,
    FileCowrieCommandRuleCatalog,
)


class CommandRuleCatalog(Protocol):
    """Small lookup contract used by tests and the JSON-backed runtime catalog."""

    def match(self, command: str) -> tuple[CowrieCommandRule, ...]:
        """Return reviewed command mapping rules matching command."""
        ...


def load_observations(path: Path) -> list[dict[str, object]]:
    """Load sanitized Cowrie observations from the runtime JSON file.

    Expected file shape:
        {"observations": [{...CowrieObservation...}]}
    """
    if not path.exists():
        return []

    payload = json.loads(path.read_text(encoding="utf-8"))
    observations = payload.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError(f"{path} must contain an observations list")
    return [item for item in observations if isinstance(item, dict)]


def summarize_commands(
    observations: list[dict[str, object]],
    catalog: CommandRuleCatalog,
) -> dict[str, object]:
    """Build a deterministic command coverage report.

    Only `cowrie.command.input` observations are counted. `cowrie.command.failed`
    is intentionally ignored here because failed events are observation-only and
    should not drive profiler coverage.
    """
    command_counts: Counter[str] = Counter()
    attackers_by_command: dict[str, set[str]] = defaultdict(set)
    sessions_by_command: dict[str, set[str]] = defaultdict(set)
    first_seen: dict[str, str] = {}
    last_seen: dict[str, str] = {}

    for observation in observations:
        if observation.get("eventid") != "cowrie.command.input":
            continue
        command = observation.get("command")
        if not isinstance(command, str) or not command.strip():
            continue

        normalized_command = command.strip()
        command_counts[normalized_command] += 1

        attacker_key = observation.get("attacker_key")
        if isinstance(attacker_key, str) and attacker_key:
            attackers_by_command[normalized_command].add(attacker_key)

        session = observation.get("session")
        if isinstance(session, str) and session:
            sessions_by_command[normalized_command].add(session)

        timestamp = observation.get("ts")
        if isinstance(timestamp, str) and timestamp:
            if normalized_command not in first_seen or timestamp < first_seen[normalized_command]:
                first_seen[normalized_command] = timestamp
            if normalized_command not in last_seen or timestamp > last_seen[normalized_command]:
                last_seen[normalized_command] = timestamp

    command_rows = [
        _command_row(
            command=command,
            count=count,
            catalog=catalog,
            attackers=attackers_by_command[command],
            sessions=sessions_by_command[command],
            first_seen=first_seen.get(command),
            last_seen=last_seen.get(command),
        )
        for command, count in sorted(
            command_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]

    mapped_rows = [row for row in command_rows if row["mapped"]]
    unmapped_rows = [row for row in command_rows if not row["mapped"]]
    return {
        "schema_version": "v1",
        "total_command_input_events": sum(command_counts.values()),
        "unique_commands": len(command_rows),
        "mapped_unique_commands": len(mapped_rows),
        "unmapped_unique_commands": len(unmapped_rows),
        "commands": command_rows,
        "unmapped_commands": unmapped_rows,
    }


def write_report(report: dict[str, object], path: Path) -> None:
    """Write a JSON report, creating the parent directory when needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def print_summary(report: dict[str, object]) -> None:
    """Print a compact human-readable summary for terminal use."""
    print(
        "Cowrie command coverage: "
        f"{report['mapped_unique_commands']}/{report['unique_commands']} "
        "unique commands mapped"
    )
    print(f"Total command.input events: {report['total_command_input_events']}")

    unmapped = report.get("unmapped_commands", [])
    if not unmapped:
        print("Unmapped commands: none")
        return

    print("Top unmapped commands:")
    for row in unmapped[:10]:
        if isinstance(row, dict):
            print(f"  {row.get('count', 0)}x {row.get('command', '<unknown>')}")


def _command_row(
    command: str,
    count: int,
    catalog: CommandRuleCatalog,
    attackers: set[str],
    sessions: set[str],
    first_seen: str | None,
    last_seen: str | None,
) -> dict[str, object]:
    rules = catalog.match(command)
    techniques = [
        {
            "rule_name": rule.name,
            "technique_id": rule.technique_id,
            "confidence": rule.confidence,
        }
        for rule in rules
    ]
    return {
        "command": command,
        "count": count,
        "mapped": bool(techniques),
        "techniques": techniques,
        "attackers": sorted(attackers),
        "sessions": sorted(sessions),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize Cowrie command coverage against reviewed mappings.",
    )
    parser.add_argument(
        "--observations-file",
        type=Path,
        default=Path("data/runtime/cowrie_observations.json"),
        help="Path to data/runtime/cowrie_observations.json.",
    )
    parser.add_argument(
        "--mapping-file",
        type=Path,
        default=Path("data/cowrie/command_mapping_rules.json"),
        help="Path to Cowrie command mapping rules.",
    )
    parser.add_argument(
        "--write-report",
        type=Path,
        default=None,
        help="Optional JSON report output path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    observations = load_observations(args.observations_file)
    report = summarize_commands(
        observations,
        FileCowrieCommandRuleCatalog(args.mapping_file),
    )
    print_summary(report)
    if args.write_report is not None:
        write_report(report, args.write_report)
        print(f"Wrote report: {args.write_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
