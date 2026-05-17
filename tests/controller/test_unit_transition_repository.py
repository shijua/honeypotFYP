from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.controller.repository import FileTechniqueTransitionRepository


pytestmark = pytest.mark.unit


def test_file_transition_repository_returns_recency_weighted_top_k(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1552.001": {
                        "T1213": {"probability": 0.6, "support": 3},
                        "T1005": {"probability": 0.3, "support": 1},
                    },
                    "T1046": {
                        "T1005": {"probability": 0.9, "support": 2},
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=1)

    assert repository.degraded_reason is None
    assert repository.score_transition("T1552.001", "T1213") == 0.6
    assert repository.next_scores(["T1552.001", "T1046"], top_k=2) == {
        "T1005": 0.9,
        "T1213": 0.3,
    }


def test_file_transition_repository_degrades_when_prior_is_missing(tmp_path: Path) -> None:
    repository = FileTechniqueTransitionRepository(tmp_path / "missing.json")

    assert repository.degraded_reason
    assert repository.score_transition("T1552.001", "T1213") == 0.0
    assert repository.next_scores(["T1552.001"], top_k=5) == {}


def test_file_transition_repository_filters_low_support(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1552.001": {
                        "T1213": {"probability": 0.8, "support": 1},
                        "T1005": {"probability": 0.5, "support": 3},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=2)

    assert repository.score_transition("T1552.001", "T1213") == 0.0
    assert repository.next_scores(["T1552.001"], top_k=5) == {"T1005": 0.5}


def test_file_transition_repository_keeps_global_fallback_edges(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1552.001": {
                        "T1213": {"probability": 0.03, "support": 0, "fallback": True},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=2)

    assert repository.score_transition("T1552.001", "T1213") == 0.03
    assert repository.next_scores(["T1552.001"], top_k=5) == {"T1213": 0.03}


def test_file_transition_repository_boosts_supported_order2_context(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1002": {
                        "T1003": {"probability": 0.2, "support": 2},
                        "T1004": {"probability": 0.5, "support": 2},
                    }
                },
                "order2_transitions": {
                    "T1001|T1002": {
                        "T1003": {"probability": 0.9, "support": 2},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=1, order2_min_support=2)

    assert repository.next_scores(["T1001", "T1002"], top_k=5) == {
        "T1004": 0.5,
        "T1003": 0.375,
    }


def test_file_transition_repository_ignores_low_support_order2_context(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1002": {
                        "T1003": {"probability": 0.2, "support": 2},
                    }
                },
                "order2_transitions": {
                    "T1001|T1002": {
                        "T1003": {"probability": 0.9, "support": 1},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=1, order2_min_support=2)

    assert repository.next_scores(["T1001", "T1002"], top_k=5) == {"T1003": 0.2}


def test_file_transition_repository_uses_supported_order3_context(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1003": {
                        "T1004": {"probability": 0.3, "support": 3},
                    }
                },
                "order2_transitions": {
                    "T1002|T1003": {
                        "T1005": {"probability": 0.5, "support": 2},
                    }
                },
                "order3_transitions": {
                    "T1001|T1002|T1003": {
                        "T1005": {"probability": 0.9, "support": 3},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=1, order2_min_support=2, order3_min_support=3)

    assert repository.next_scores(["T1001", "T1002", "T1003"], top_k=5) == {
        "T1004": 0.3,
        "T1005": 0.3375,
    }


def test_file_transition_repository_ignores_low_support_order3_context(tmp_path: Path) -> None:
    prior_path = tmp_path / "prior.json"
    prior_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "transitions": {
                    "T1003": {
                        "T1004": {"probability": 0.3, "support": 3},
                    }
                },
                "order3_transitions": {
                    "T1001|T1002|T1003": {
                        "T1005": {"probability": 0.9, "support": 1},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    repository = FileTechniqueTransitionRepository(prior_path, min_support=1, order3_min_support=3)

    assert repository.next_scores(["T1001", "T1002", "T1003"], top_k=5) == {"T1004": 0.3}
