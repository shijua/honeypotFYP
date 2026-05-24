#!/usr/bin/env python3
"""Build the ATT&CK group-technique collaborative-filtering prior.

The builder reads a local Enterprise ATT&CK STIX bundle and extracts
`intrusion-set --uses--> attack-pattern` relationships. It does not fetch data
or infer missing labels.

Example:
    python scripts/data/build_attack_group_prior.py \
      --stix data/mitre/enterprise-attack.json \
      --output data/technique_prior/attack_group_technique_prior.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an ATT&CK group-technique prior from Enterprise ATT&CK STIX.",
    )
    parser.add_argument(
        "--stix",
        type=Path,
        default=Path("data/mitre/enterprise-attack.json"),
        help="Local Enterprise ATT&CK STIX bundle.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/technique_prior/attack_group_technique_prior.json"),
        help="Output JSON path for the derived group-technique prior.",
    )
    args = parser.parse_args()

    prior = build_attack_group_prior(args.stix)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(prior, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote ATT&CK group prior to {args.output}")
    print(
        f"groups={prior['group_count']} techniques={prior['technique_count']} "
        f"relationships={prior['relationship_count']}"
    )
    return 0


def build_attack_group_prior(stix_path: Path) -> dict[str, Any]:
    """Return a serializable group-technique prior from one STIX bundle.

    Example:
        intrusion-set G uses attack-pattern T1190 -> groups[0].techniques contains "T1190".
    """
    payload = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = payload.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError(f"{stix_path} does not contain a STIX objects list")

    groups_by_id = {
        str(item["id"]): item
        for item in objects
        if _is_active_type(item, "intrusion-set") and isinstance(item.get("id"), str)
    }
    techniques_by_id = {
        str(item["id"]): _attack_technique_id(item)
        for item in objects
        if _is_active_type(item, "attack-pattern") and isinstance(item.get("id"), str)
    }
    techniques_by_id = {
        stix_id: technique_id
        for stix_id, technique_id in techniques_by_id.items()
        if technique_id is not None
    }

    techniques_by_group: dict[str, set[str]] = {group_id: set() for group_id in groups_by_id}
    relationship_count = 0
    for item in objects:
        if not _is_active_type(item, "relationship"):
            continue
        if item.get("relationship_type") != "uses":
            continue
        source_ref = item.get("source_ref")
        target_ref = item.get("target_ref")
        if not isinstance(source_ref, str) or not isinstance(target_ref, str):
            continue
        if source_ref not in groups_by_id or target_ref not in techniques_by_id:
            continue
        relationship_count += 1
        techniques_by_group[source_ref].add(techniques_by_id[target_ref])

    groups = [
        {
            "group_id": group_id,
            "name": str(groups_by_id[group_id].get("name", group_id)),
            "techniques": sorted(techniques),
        }
        for group_id, techniques in techniques_by_group.items()
        if techniques
    ]
    groups.sort(key=lambda item: (item["name"], item["group_id"]))
    all_techniques = sorted({technique for group in groups for technique in group["techniques"]})
    return {
        "schema_version": "v1",
        "source": str(stix_path),
        "method": "attack_group_technique_collaborative_filtering",
        "group_count": len(groups),
        "technique_count": len(all_techniques),
        "relationship_count": relationship_count,
        "groups": groups,
        "build_report": {
            "stix_objects": len(objects),
            "active_intrusion_sets": len(groups_by_id),
            "active_attack_patterns_with_attack_id": len(techniques_by_id),
            "groups_without_techniques": len(groups_by_id) - len(groups),
        },
    }


def _is_active_type(item: object, expected_type: str) -> bool:
    """Return True for non-revoked, non-deprecated STIX objects of one type."""
    if not isinstance(item, dict) or item.get("type") != expected_type:
        return False
    return not bool(item.get("revoked")) and not bool(item.get("x_mitre_deprecated"))


def _attack_technique_id(item: dict[str, Any]) -> str | None:
    """Extract the external ATT&CK technique id from an attack-pattern object.

    Example:
        external_references=[{"source_name":"mitre-attack","external_id":"T1190"}]
        -> "T1190".
    """
    refs = item.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        external_id = ref.get("external_id")
        if ref.get("source_name") == "mitre-attack" and isinstance(external_id, str):
            if external_id.startswith("T"):
                return external_id
    return None


if __name__ == "__main__":
    raise SystemExit(main())
