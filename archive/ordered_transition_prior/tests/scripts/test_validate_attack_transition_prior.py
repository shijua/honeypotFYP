from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validation.attack_transition_prior import build_report


pytestmark = pytest.mark.unit


def test_validate_attack_transition_prior_accepts_nonempty_prior(tmp_path: Path) -> None:
    path = tmp_path / "prior.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1552.001": {
                        "T1213": {"probability": 0.7, "support": 2}
                    }
                },
                "order2_transitions": {
                    "T1083|T1552.001": {
                        "T1213": {"probability": 0.9, "support": 2}
                    }
                },
                "order3_transitions": {
                    "T1046|T1083|T1552.001": {
                        "T1213": {"probability": 0.95, "support": 3}
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    report = build_report(path, min_support=1)

    assert report["ok"] is True
    assert report["transition_count"] == 1
    assert report["order2_transition_count"] == 1
    assert report["order3_transition_count"] == 1


def test_validate_attack_transition_prior_accepts_fallback_edges_with_zero_support(tmp_path: Path) -> None:
    path = tmp_path / "prior.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1552.001": {
                        "T1213": {"probability": 0.02, "support": 0, "fallback": True}
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    report = build_report(path, min_support=1)

    assert report["ok"] is True
    assert report["transition_count"] == 1


def test_validate_attack_transition_prior_rejects_missing_or_empty_prior(tmp_path: Path) -> None:
    missing = build_report(tmp_path / "missing.json", min_support=1)
    empty_path = tmp_path / "empty.json"
    empty_path.write_text(json.dumps({"transitions": {}}), encoding="utf-8")
    empty = build_report(empty_path, min_support=1)

    assert missing["status"] == "missing"
    assert missing["ok"] is False
    assert empty["status"] == "invalid"
    assert empty["ok"] is False
