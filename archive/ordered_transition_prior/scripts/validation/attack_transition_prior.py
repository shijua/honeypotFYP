#!/usr/bin/env python3
"""Validate that the public-dataset technique transition prior is usable.

Example:
    python scripts/validation/attack_transition_prior.py --path data/transitions/technique_transition_prior.json

Output:
    {"ok": true, "transition_count": 42, ...}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    """Print a validation report and return non-zero when the prior is unusable."""
    parser = argparse.ArgumentParser(description="Validate the generated ATT&CK transition prior.")
    parser.add_argument("--path", default="data/transitions/technique_transition_prior.json")
    parser.add_argument("--min-support", type=int, default=1)
    args = parser.parse_args()

    report = build_report(Path(args.path), min_support=args.min_support)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


def build_report(path: Path, *, min_support: int) -> dict[str, Any]:
    """Return schema/count checks for one transition-prior JSON file.

    Example:
        build_report(Path("prior.json"), min_support=1) -> {"ok": true, "transition_count": 5, "order2_transition_count": 3, "order3_transition_count": 2}
    """
    if not path.exists():
        return {
            "schema_version": "v1",
            "path": str(path),
            "ok": False,
            "status": "missing",
            "error": "transition prior file does not exist",
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "schema_version": "v1",
            "path": str(path),
            "ok": False,
            "status": "unreadable",
            "error": str(exc),
        }
    transitions = payload.get("transitions") if isinstance(payload, dict) else None
    if not isinstance(transitions, dict):
        return {
            "schema_version": "v1",
            "path": str(path),
            "ok": False,
            "status": "invalid",
            "error": "transitions must be an object",
        }

    invalid_edges: list[dict[str, Any]] = []
    transition_count = 0
    for source, destinations in transitions.items():
        if not isinstance(destinations, dict):
            invalid_edges.append({"from_technique": source, "error": "destinations must be an object"})
            continue
        for destination, edge in destinations.items():
            if not isinstance(edge, dict):
                invalid_edges.append({"from_technique": source, "to_technique": destination, "error": "edge must be an object"})
                continue
            fallback = bool(edge.get("fallback"))
            support = int(edge.get("support", edge.get("count", 0)) or 0)
            probability = edge.get("probability")
            if (support < min_support and not fallback) or not isinstance(probability, (int, float)):
                invalid_edges.append(
                    {
                        "from_technique": source,
                        "to_technique": destination,
                        "support": support,
                        "probability": probability,
                        "fallback": fallback,
                    }
                )
                continue
            transition_count += 1
    order2_transitions = payload.get("order2_transitions") if isinstance(payload, dict) else None
    order2_transition_count = _count_optional_edges(order2_transitions)
    order3_transitions = payload.get("order3_transitions") if isinstance(payload, dict) else None
    order3_transition_count = _count_optional_edges(order3_transitions)

    return {
        "schema_version": "v1",
        "path": str(path),
        "ok": transition_count > 0 and not invalid_edges,
        "status": "ok" if transition_count > 0 and not invalid_edges else "invalid",
        "transition_count": transition_count,
        "order2_transition_count": order2_transition_count,
        "order3_transition_count": order3_transition_count,
        "source_count": len(transitions),
        "invalid_edges": invalid_edges,
    }


def _count_optional_edges(transitions: Any) -> int:
    """Return a best-effort edge count for optional transition sections.

    Example:
        Input:
            {"T1001|T1002": {"T1003": {"probability": 1.0}}}
        Output:
            1
    """
    if not isinstance(transitions, dict):
        return 0
    count = 0
    for destinations in transitions.values():
        if isinstance(destinations, dict):
            count += sum(1 for edge in destinations.values() if isinstance(edge, dict))
    return count


if __name__ == "__main__":
    raise SystemExit(main())
