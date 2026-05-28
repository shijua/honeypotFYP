from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.data.build_attack_hypothesis_model import build_attack_hypothesis_model


pytestmark = pytest.mark.unit


def test_build_attack_hypothesis_model_clusters_groups_and_likelihoods(tmp_path: Path) -> None:
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(_fixture_stix()), encoding="utf-8")

    model = build_attack_hypothesis_model(stix_path, k_candidates=(2,), alpha=1.0)

    assert model["schema_version"] == "v1"
    assert model["selected_k"] == 2
    assert model["group_count"] == 4
    assert model["technique_count"] == 4
    assert model["selected_metric"] == "jaccard"
    assert model["silhouette_report"] == [
        {"metric": "cosine", "k": 2, "score": model["selected_silhouette_score"]},
        {"metric": "jaccard", "k": 2, "score": model["selected_silhouette_score"]},
    ]
    assert len(model["hypotheses"]) == 2
    all_likelihoods = {
        hypothesis["hypothesis_id"]: hypothesis["likelihoods"]
        for hypothesis in model["hypotheses"]
    }
    assert set(all_likelihoods) == {"hypothesis-1", "hypothesis-2"}
    for likelihoods in all_likelihoods.values():
        assert set(likelihoods) == {"T1005", "T1046", "T1105", "T1552.001"}
        assert all(0 < value < 1 for value in likelihoods.values())


def test_build_attack_hypothesis_model_can_filter_to_catalog_covered_techniques(tmp_path: Path) -> None:
    stix_path = tmp_path / "enterprise-attack.json"
    stix_path.write_text(json.dumps(_fixture_stix()), encoding="utf-8")
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        json.dumps(
            [
                {
                    "asset_id": "finance-share",
                    "default_settings": {
                        "selection_profile": {"covered_techniques": ["T1552.001"]},
                        "configuration_variants": [
                            {"configuration_id": "finance-index", "covered_techniques": ["T1005"]}
                        ],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )

    model = build_attack_hypothesis_model(
        stix_path,
        k_candidates=(2,),
        metric="jaccard",
        technique_filter="catalog-covered",
        catalog_path=catalog_path,
    )

    assert model["selected_metric"] == "jaccard"
    assert model["technique_filter"] == "catalog-covered"
    assert model["technique_count"] == 2
    assert model["build_report"]["dropped_groups_after_filter"] == 2
    for hypothesis in model["hypotheses"]:
        assert set(hypothesis["likelihoods"]) == {"T1005", "T1552.001"}


def _fixture_stix() -> dict[str, object]:
    objects: list[dict[str, object]] = []
    for group_id, name in [
        ("intrusion-set--a1", "Alpha 1"),
        ("intrusion-set--a2", "Alpha 2"),
        ("intrusion-set--b1", "Beta 1"),
        ("intrusion-set--b2", "Beta 2"),
    ]:
        objects.append({"type": "intrusion-set", "id": group_id, "name": name})
    for technique in ["T1005", "T1046", "T1105", "T1552.001"]:
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{technique.lower().replace('.', '-')}",
                "external_references": [{"source_name": "mitre-attack", "external_id": technique}],
            }
        )
    relationships = {
        "intrusion-set--a1": ["T1005", "T1552.001"],
        "intrusion-set--a2": ["T1005", "T1552.001"],
        "intrusion-set--b1": ["T1046", "T1105"],
        "intrusion-set--b2": ["T1046", "T1105"],
    }
    for group_id, techniques in relationships.items():
        for technique in techniques:
            objects.append(
                {
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": group_id,
                    "target_ref": f"attack-pattern--{technique.lower().replace('.', '-')}",
                }
            )
    return {"type": "bundle", "objects": objects}
