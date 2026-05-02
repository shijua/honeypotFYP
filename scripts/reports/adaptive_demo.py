#!/usr/bin/env python3
"""CLI compatibility wrapper for dashboard runtime summaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from services.dashboard import summary as _summary

DockerStatusProbe = _summary.DockerStatusProbe
current_docker_status = _summary.current_docker_status


def summarize_demo(state_dir: Path) -> dict[str, Any]:
    """Build a report while preserving monkeypatch-friendly script semantics."""
    original_probe = _summary.current_docker_status
    _summary.current_docker_status = current_docker_status
    try:
        return _summary.summarize_demo(state_dir)
    finally:
        _summary.current_docker_status = original_probe


def write_report(report: dict[str, Any], path: Path) -> None:
    """Write the adaptive runtime report to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def print_summary(report: dict[str, Any]) -> None:
    """Print a compact terminal summary of the runtime report."""
    attackers = report.get("attackers", [])
    print(f"Adaptive summary: {len(attackers)} attacker(s)")
    for attacker in attackers:
        if not isinstance(attacker, dict):
            continue
        tactics = ", ".join(attacker.get("recent_tactics", [])) or "none"
        assets = attacker.get("current_running_assets", [])
        asset_ids = ", ".join(
            str(asset.get("asset_id"))
            for asset in assets
            if isinstance(asset, dict) and asset.get("asset_id")
        ) or "none"
        print(f"- {attacker.get('attacker_key')}: tactics={tactics}; assets={asset_ids}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize honeynet runtime state.")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path("data/runtime"),
        help="Directory containing runtime JSON files.",
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
    report = summarize_demo(args.state_dir)
    print_summary(report)
    if args.write_report is not None:
        write_report(report, args.write_report)
        print(f"Wrote report: {args.write_report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
