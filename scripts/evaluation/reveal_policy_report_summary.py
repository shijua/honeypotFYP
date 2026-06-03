#!/usr/bin/env python3
"""Print Markdown summary tables for reveal-policy reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from scripts.evaluation.reveal_policy import format_reveal_policy_report_summary


def main() -> int:
    """Read one or more reveal-policy JSON reports and print thesis-ready tables."""
    parser = argparse.ArgumentParser(description="Print Markdown summary tables for reveal-policy JSON reports.")
    parser.add_argument("reports", nargs="+", type=Path, help="Reveal-policy JSON report path.")
    args = parser.parse_args()

    named_reports: list[tuple[str, dict[str, Any]]] = []
    for path in args.reports:
        named_reports.append((_report_label(path), json.loads(path.read_text(encoding="utf-8"))))
    print(format_reveal_policy_report_summary(named_reports))
    return 0


def _report_label(path: Path) -> str:
    stem = path.stem
    if "main" in stem:
        return "Main multi-step scenarios"
    if "regression" in stem:
        return "Regression edge-case scenarios"
    return stem.replace("_", " ").replace("-", " ").title()


if __name__ == "__main__":
    raise SystemExit(main())
