#!/usr/bin/env python3
"""Validate high-interaction assets and their telemetry path.

This is a focused wrapper around `asset_telemetry.py` for the assets that are
supposed to run as upgraded backends rather than static story pages.

Example:
    .venv/bin/python scripts/validation/high_interaction_assets.py --require-observed
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.validation.asset_telemetry import build_report


HIGH_INTERACTION_ASSETS = {
    "admin-jumpbox",
    "conpot-plc",
    "dionaea-capture",
    "honeytrap-generic",
    "log4shell-app",
    "spring-gateway-app",
}


def main() -> int:
    """Print a high-interaction validation report and return a shell status."""
    parser = argparse.ArgumentParser(description="Validate high-interaction asset telemetry.")
    parser.add_argument("--catalog", default="data/assets/catalog.json")
    parser.add_argument("--state-dir", default="data/runtime")
    parser.add_argument("--require-observed", action="store_true")
    args = parser.parse_args()

    report = build_report(
        catalog_path=Path(args.catalog),
        state_dir=Path(args.state_dir),
        asset_ids=HIGH_INTERACTION_ASSETS,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.require_observed and any(not item["ok"] for item in report["assets"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

