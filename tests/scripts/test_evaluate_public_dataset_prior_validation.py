from __future__ import annotations

import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from libs.common.config import RuntimeConfig
from scripts.evaluation.public_dataset_prior_validation import (
    evaluate_public_dataset_prior,
    extract_dataset_traces,
)


pytestmark = pytest.mark.unit


def _write_prior(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "method": "attack_group_technique_collaborative_filtering",
                "groups": [
                    {
                        "group_id": f"G000{index}",
                        "name": f"Fixture Group {index}",
                        "techniques": ["T1190", "T1105", "T1608"],
                    }
                    for index in range(1, 5)
                ]
                + [
                    {
                        "group_id": "G0099",
                        "name": "Unrelated",
                        "techniques": ["T1046"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_public_dataset_prior_validation_extracts_csv_jsonl_and_zip(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "datasets"
    dataset.mkdir()
    (dataset / "trace.csv").write_text(
        "timestamp,technique_id,message\n"
        "2026-01-01T00:00:01Z,T1190,exploit\n"
        "2026-01-01T00:00:02Z,T1105,download\n",
        encoding="utf-8",
    )
    (dataset / "trace.jsonl").write_text(
        json.dumps({"time": "2", "technique": "attack.t1608"}) + "\n"
        + json.dumps({"time": "1", "technique": "attack.t1190"}) + "\n",
        encoding="utf-8",
    )
    with ZipFile(dataset / "bundle.zip", "w") as archive:
        archive.writestr(
            "nested/labels.yaml",
            "events:\n"
            "  - ts: 1\n"
            "    mitre_attack: T1190\n"
            "  - ts: 2\n"
            "    mitre_attack: T1105\n",
        )

    extraction = extract_dataset_traces([dataset])

    assert extraction["file_count"] == 3
    assert len(extraction["traces"]) == 3
    assert {tuple(trace["techniques"]) for trace in extraction["traces"]} == {
        ("T1190", "T1105"),
        ("T1190", "T1608"),
    }


def test_public_dataset_prior_validation_reports_prior_metrics(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior.json"
    _write_prior(prior)
    dataset = tmp_path / "datasets"
    dataset.mkdir()
    (dataset / "trace.json").write_text(
        json.dumps(
            {
                "events": [
                    {"timestamp": "1", "technique": "T1190"},
                    {"timestamp": "2", "technique": "T1105"},
                    {"timestamp": "3", "technique": "T1608"},
                ]
            }
        ),
        encoding="utf-8",
    )

    report = evaluate_public_dataset_prior(
        dataset_paths=[dataset],
        prior_path=prior,
        config=RuntimeConfig(),
    )

    assert report["ok"] is True
    assert report["trace_count"] == 1
    assert report["dataset_sources"] == ["datasets"]
    assert report["top_k"] == 40
    assert [row["top_k"] for row in report["k_sweep"]] == [5, 10, 20, 40]
    assert "rank_sweep" not in report
    assert report["support_threshold"] == 0.15
    assert report["metrics"]["prefix_count"] == 2
    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["metrics"]["mrr"] == 1.0
    diagnostics = report["dataset_diagnostics"]
    assert diagnostics["unique_technique_family_count"] == 3
    assert diagnostics["prior_overlap"]["dataset_family_covered_by_prior_rate"] == 1.0
    assert diagnostics["concentration"]["top_3_share"] == 1.0
    assert diagnostics["top_technique_families"][0]["technique"] == "T1105"
    assert diagnostics["source_breakdown"][0]["source"] == "datasets"


def test_public_dataset_prior_validation_reports_contributing_dataset_names(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior.json"
    _write_prior(prior)
    dataset_root = tmp_path / "vendor" / "datasets"
    casinolimit = dataset_root / "casinolimit"
    lab_traces = dataset_root / "lab-traces"
    casinolimit.mkdir(parents=True)
    lab_traces.mkdir(parents=True)
    (casinolimit / "trace.csv").write_text(
        "timestamp,technique_id\n1,T1190\n2,T1105\n",
        encoding="utf-8",
    )
    (lab_traces / "trace.jsonl").write_text(
        json.dumps({"timestamp": "1", "technique": "T1190"}) + "\n"
        + json.dumps({"timestamp": "2", "technique": "T1608"}) + "\n",
        encoding="utf-8",
    )

    report = evaluate_public_dataset_prior(
        dataset_paths=[dataset_root],
        prior_path=prior,
        config=RuntimeConfig(),
    )

    assert report["ok"] is True
    assert report["dataset_sources"] == ["casinolimit", "lab-traces"]
    assert [row["source"] for row in report["dataset_diagnostics"]["source_breakdown"]] == [
        "casinolimit",
        "lab-traces",
    ]


def test_public_dataset_prior_validation_fails_without_traces(
    tmp_path: Path,
) -> None:
    prior = tmp_path / "prior.json"
    _write_prior(prior)
    dataset = tmp_path / "datasets"
    dataset.mkdir()
    (dataset / "notes.txt").write_text("no labelled ATT&CK trace here", encoding="utf-8")
    (dataset / "single.csv").write_text("technique\nT1190\n", encoding="utf-8")

    report = evaluate_public_dataset_prior(
        dataset_paths=[dataset],
        prior_path=prior,
        config=RuntimeConfig(),
    )

    assert report["ok"] is False
    assert report["trace_count"] == 0
    assert report["metrics"]["prefix_count"] == 0


def test_public_dataset_prior_validation_skips_oversized_files(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "datasets"
    dataset.mkdir()
    (dataset / "large.csv").write_text(
        "timestamp,technique_id\n"
        "1,T1190\n"
        "2,T1105\n",
        encoding="utf-8",
    )
    with ZipFile(dataset / "bundle.zip", "w") as archive:
        archive.writestr("large.jsonl", '{"technique": "T1190"}\n{"technique": "T1105"}\n')

    extraction = extract_dataset_traces([dataset], max_file_bytes=10)

    assert extraction["traces"] == []
    assert extraction["skipped_file_count"] == 2
    assert len(extraction["skipped_files"]) == 2
    assert all("file too large" in item["reason"] for item in extraction["skipped_files"])
