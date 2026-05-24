from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.data.build_attack_group_prior import build_attack_group_prior


pytestmark = pytest.mark.unit


def test_build_attack_group_prior_extracts_active_group_uses_relationships(tmp_path: Path) -> None:
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"type": "intrusion-set", "id": "intrusion-set--g1", "name": "Fixture Group"},
                    {"type": "intrusion-set", "id": "intrusion-set--deprecated", "name": "Old", "x_mitre_deprecated": True},
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--t1190",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
                    },
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--t1059",
                        "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}],
                    },
                    {
                        "type": "relationship",
                        "relationship_type": "uses",
                        "source_ref": "intrusion-set--g1",
                        "target_ref": "attack-pattern--t1190",
                    },
                    {
                        "type": "relationship",
                        "relationship_type": "uses",
                        "source_ref": "intrusion-set--g1",
                        "target_ref": "attack-pattern--t1059",
                    },
                    {
                        "type": "relationship",
                        "relationship_type": "uses",
                        "source_ref": "intrusion-set--deprecated",
                        "target_ref": "attack-pattern--t1059",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    prior = build_attack_group_prior(stix_path)

    assert prior["group_count"] == 1
    assert prior["technique_count"] == 2
    assert prior["relationship_count"] == 2
    assert prior["groups"] == [
        {
            "group_id": "intrusion-set--g1",
            "name": "Fixture Group",
            "techniques": ["T1059", "T1190"],
        }
    ]
