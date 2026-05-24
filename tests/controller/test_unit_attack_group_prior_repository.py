from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.controller.repository import FileAttackGroupTechniquePriorRepository


pytestmark = pytest.mark.unit


def test_attack_group_prior_recommends_unseen_techniques_from_similar_groups(tmp_path: Path) -> None:
    prior_path = tmp_path / "attack_group_prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "groups": [
                    {"group_id": "G1", "name": "Web Group", "techniques": ["T1190", "T1059", "T1105"]},
                    {"group_id": "G2", "name": "Credential Group", "techniques": ["T1552.001", "T1005"]},
                ],
            }
        ),
        encoding="utf-8",
    )

    repository = FileAttackGroupTechniquePriorRepository(prior_path)

    assert repository.degraded_reason is None
    assert repository.recommend({"T1190"}, top_k=3, support_threshold=0.1) == {
        "T1059": 0.666667,
        "T1105": 0.666667,
    }


def test_attack_group_prior_reports_degraded_missing_file(tmp_path: Path) -> None:
    repository = FileAttackGroupTechniquePriorRepository(tmp_path / "missing.json")

    assert repository.degraded_reason
    assert repository.recommend({"T1190"}, top_k=3, support_threshold=0.1) == {}
