from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validation.attack_group_prior import build_report


pytestmark = pytest.mark.unit


def test_validate_attack_group_prior_accepts_nonempty_prior(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps({"groups": [{"group_id": "G1", "name": "Group", "techniques": ["T1190", "T1059"]}]}),
        encoding="utf-8",
    )

    report = build_report(prior_path)

    assert report["ok"] is True
    assert report["group_count"] == 1
    assert report["technique_count"] == 2


def test_validate_attack_group_prior_rejects_missing_or_empty_prior(tmp_path: Path) -> None:
    missing = build_report(tmp_path / "missing.json")
    assert missing["ok"] is False
    assert missing["status"] == "missing"

    empty_path = tmp_path / "empty.json"
    empty_path.write_text(json.dumps({"groups": []}), encoding="utf-8")
    empty = build_report(empty_path)
    assert empty["ok"] is False
    assert empty["status"] == "invalid"
