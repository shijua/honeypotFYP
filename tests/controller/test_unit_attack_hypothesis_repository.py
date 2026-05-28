from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.controller.repository import FileAttackHypothesisRepository


pytestmark = pytest.mark.unit


def test_hypothesis_repository_returns_uniform_prior_without_observed_techniques(tmp_path: Path) -> None:
    path = _write_model(tmp_path)
    repository = FileAttackHypothesisRepository(path)

    posterior = repository.posterior(set())

    assert posterior.degraded_reason is None
    assert posterior.posterior == {"credential": 0.5, "transfer": 0.5}
    assert [item["hypothesis_id"] for item in posterior.top_hypotheses] == ["credential", "transfer"]


def test_hypothesis_repository_updates_and_normalizes_posterior(tmp_path: Path) -> None:
    path = _write_model(tmp_path)
    repository = FileAttackHypothesisRepository(path)

    posterior = repository.posterior({"T1005"})

    assert posterior.posterior == {"credential": 0.8, "transfer": 0.2}
    assert posterior.top_hypotheses[0]["hypothesis_id"] == "credential"
    assert posterior.skipped_techniques == ()


def test_hypothesis_repository_reports_unknown_techniques(tmp_path: Path) -> None:
    path = _write_model(tmp_path)
    repository = FileAttackHypothesisRepository(path)

    posterior = repository.posterior({"T9999"})

    assert posterior.posterior == {"credential": 0.5, "transfer": 0.5}
    assert posterior.skipped_techniques == ("T9999",)


def test_hypothesis_repository_degrades_when_missing(tmp_path: Path) -> None:
    repository = FileAttackHypothesisRepository(tmp_path / "missing.json")

    posterior = repository.posterior({"T1005"})

    assert posterior.posterior == {}
    assert posterior.degraded_reason is not None


def _write_model(tmp_path: Path) -> Path:
    path = tmp_path / "hypothesis.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "hypotheses": [
                    {
                        "hypothesis_id": "credential",
                        "label": "credential",
                        "top_techniques": [{"technique": "T1005", "likelihood": 0.8}],
                        "likelihoods": {"T1005": 0.8, "T1105": 0.2},
                    },
                    {
                        "hypothesis_id": "transfer",
                        "label": "transfer",
                        "top_techniques": [{"technique": "T1105", "likelihood": 0.8}],
                        "likelihoods": {"T1005": 0.2, "T1105": 0.8},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path
