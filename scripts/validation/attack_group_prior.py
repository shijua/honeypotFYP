#!/usr/bin/env python3
"""Validate the ATT&CK group-technique recommendation prior.

Example:
    python scripts/validation/attack_group_prior.py --path data/technique_prior/attack_group_technique_prior.json

Output:
    {"ok": true, "group_count": 168, "technique_count": 488, ...}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the generated ATT&CK group-technique prior.")
    parser.add_argument("--path", default="data/technique_prior/attack_group_technique_prior.json")
    args = parser.parse_args()

    report = build_report(Path(args.path))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def build_report(path: Path) -> dict[str, Any]:
    """Return schema/count checks for one group-prior JSON file.

    Example:
        build_report(Path("prior.json")) -> {"ok": true, "group_count": 2, "technique_count": 5}
    """
    if not path.exists():
        return {"schema_version": "v1", "path": str(path), "ok": False, "status": "missing"}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"schema_version": "v1", "path": str(path), "ok": False, "status": "unreadable", "error": str(exc)}
    groups = payload.get("groups") if isinstance(payload, dict) else None
    if not isinstance(groups, list):
        return {"schema_version": "v1", "path": str(path), "ok": False, "status": "invalid", "error": "groups must be a list"}
    invalid_groups = [
        index
        for index, group in enumerate(groups)
        if not isinstance(group, dict)
        or not isinstance(group.get("group_id"), str)
        or not isinstance(group.get("techniques"), list)
        or not any(isinstance(item, str) and item.startswith("T") for item in group.get("techniques", []))
    ]
    techniques = {
        technique
        for group in groups
        if isinstance(group, dict)
        for technique in group.get("techniques", [])
        if isinstance(technique, str)
    }
    ok = bool(groups) and not invalid_groups and bool(techniques)
    return {
        "schema_version": "v1",
        "path": str(path),
        "ok": ok,
        "status": "ok" if ok else "invalid",
        "group_count": len(groups),
        "technique_count": len(techniques),
        "invalid_group_indexes": invalid_groups,
    }


if __name__ == "__main__":
    raise SystemExit(main())
