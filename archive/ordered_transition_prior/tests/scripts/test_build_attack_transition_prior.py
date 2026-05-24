from __future__ import annotations

import json
import bz2
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts.data.build_attack_transition_prior import build_normalized_traces, build_prior, load_events


pytestmark = pytest.mark.unit


def test_build_attack_transition_prior_loads_common_file_shapes(tmp_path: Path) -> None:
    csv_path = tmp_path / "mordor.csv"
    csv_path.write_text(
        "case_id,timestamp,technique,tactic,host\n"
        "case-a,2026-01-01T00:00:00Z,T1552.001,Credential Access,web01\n"
        "case-a,2026-01-01T00:01:00Z,T1213,Collection,web01\n",
        encoding="utf-8",
    )
    jsonl_path = tmp_path / "pwnjutsu.jsonl"
    jsonl_path.write_text(
        json.dumps({"scenario": "case-b", "ts": "2026-01-01T00:00:00Z", "message": "uses T1046"}) + "\n"
        + json.dumps({"scenario": "case-b", "ts": "2026-01-01T00:02:00Z", "message": "uses T1005"}) + "\n",
        encoding="utf-8",
    )
    pwnjutsu_bz2_path = tmp_path / "pwnjutsu.json.bz2"
    pwnjutsu_bz2_path.write_bytes(
        bz2.compress(
            json.dumps(
                [
                    {"scenario": "case-bz2", "order": 1, "technique": "T1059"},
                    {"scenario": "case-bz2", "order": 2, "technique": "T1105"},
                ]
            ).encode("utf-8")
        )
    )
    yaml_path = tmp_path / "uwf-zeekdata24.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "events": [
                    {"trace_id": "case-c", "time": "2026-01-01T00:00:00Z", "technique_id": "T1083"},
                    {"trace_id": "case-c", "time": "2026-01-01T00:03:00Z", "technique_id": "T1046"},
                    {"trace_id": "case-c", "time": "2026-01-01T00:04:00Z", "description": "tactic only"},
                ]
            }
        ),
        encoding="utf-8",
    )
    zip_path = tmp_path / "casinolimit.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr(
            "events.json",
            json.dumps(
                [
                    {"mission_id": "case-d", "date": "2026-01-01T00:00:00Z", "tags": ["attack.T1110"]},
                    {"mission_id": "case-d", "date": "2026-01-01T00:01:00Z", "tags": ["attack.T1021.004"]},
                ]
            ),
        )

    events, stats = load_events([csv_path, jsonl_path, pwnjutsu_bz2_path, yaml_path, zip_path])
    prior, report = build_prior(events, stats=stats, alpha=0.0, min_support=1, global_fallback_weight=0.0)
    normalized = build_normalized_traces(events)

    assert prior["transitions"]["T1552.001"]["T1213"]["probability"] == 1.0
    assert prior["transitions"]["T1046"]["T1005"]["sources"] == ["pwnjutsu"]
    assert prior["transitions"]["T1059"]["T1105"]["sources"] == ["pwnjutsu"]
    assert prior["transitions"]["T1083"]["T1046"]["support"] == 1
    assert prior["transitions"]["T1110"]["T1021.004"]["count"] == 1
    assert report["source_counts"]["uwf-zeekdata24"]["skipped_without_technique"] == 1
    assert report["transition_count"] == 5
    assert normalized["traces"][0]["events"][0]["technique"] == "T1110"
    assert {"case_id", "source_dataset", "events"}.issubset(normalized["traces"][0])


def test_build_attack_transition_prior_applies_min_support_and_smoothing(tmp_path: Path) -> None:
    json_path = tmp_path / "windows-apt-2025.json"
    json_path.write_text(
        json.dumps(
            {
                "records": [
                    {"case_id": "case-a", "timestamp": "2026-01-01T00:00:00Z", "technique": "T1005"},
                    {"case_id": "case-a", "timestamp": "2026-01-01T00:01:00Z", "technique": "T1567"},
                    {"case_id": "case-b", "timestamp": "2026-01-01T00:00:00Z", "technique": "T1005"},
                    {"case_id": "case-b", "timestamp": "2026-01-01T00:01:00Z", "technique": "T1567"},
                    {"case_id": "case-c", "timestamp": "2026-01-01T00:00:00Z", "technique": "T1005"},
                    {"case_id": "case-c", "timestamp": "2026-01-01T00:01:00Z", "technique": "T1105"},
                ]
            }
        ),
        encoding="utf-8",
    )

    events, stats = load_events([json_path])
    prior, report = build_prior(events, stats=stats, alpha=0.1, min_support=2)

    assert set(prior["transitions"]["T1005"]) == {"T1567"}
    assert prior["transitions"]["T1005"]["T1567"]["probability"] == 1.0
    assert report["transition_count"] == 1


def test_build_attack_transition_prior_emits_order2_counts_by_count_mode(tmp_path: Path) -> None:
    dataset = tmp_path / "events.csv"
    dataset.write_text(
        "case_id,order,technique\n"
        "case-a,1,T1001\n"
        "case-a,2,T1002\n"
        "case-a,3,T1003\n"
        "case-a,4,T1001\n"
        "case-a,5,T1002\n"
        "case-a,6,T1003\n"
        "case-a,7,T1001\n"
        "case-a,8,T1002\n"
        "case-a,9,T1004\n",
        encoding="utf-8",
    )
    events, stats = load_events([dataset])

    trace_prior, trace_report = build_prior(
        events,
        stats=stats,
        alpha=0.0,
        min_support=1,
        count_mode="trace-balanced",
        global_fallback_weight=0.0,
    )
    event_prior, event_report = build_prior(
        events,
        stats=stats,
        alpha=0.0,
        min_support=1,
        count_mode="event-count",
        global_fallback_weight=0.0,
    )

    assert trace_prior["order2_transitions"]["T1001|T1002"]["T1003"]["count"] == 0.666667
    assert trace_prior["order2_transitions"]["T1001|T1002"]["T1004"]["count"] == 0.333333
    assert trace_prior["order3_transitions"]["T1001|T1002|T1003"]["T1001"]["count"] == 1
    assert event_prior["order2_transitions"]["T1001|T1002"]["T1003"]["count"] == 2
    assert event_prior["order2_transitions"]["T1001|T1002"]["T1004"]["count"] == 1
    assert event_prior["order3_transitions"]["T1001|T1002|T1003"]["T1001"]["count"] == 2
    assert trace_report["order2_transition_count"] == 4
    assert trace_report["order3_transition_count"] == 4
    assert event_report["order2_transition_count"] == 4
    assert event_report["order3_transition_count"] == 4


def test_build_attack_transition_prior_reads_real_public_dataset_shapes(tmp_path: Path) -> None:
    uwf_path = tmp_path / "vendor" / "datasets" / "uwf-zeekdata24" / "csv" / "sample.csv"
    uwf_path.parent.mkdir(parents=True)
    uwf_path.write_text(
        "src_ip_zeek,datetime,label_tactic,label_technique,service\n"
        "143.88.10.12,2024-03-18T07:03:01.395Z,Reconnaissance,T1595,http\n"
        "143.88.10.12,2024-03-18T07:05:01.395Z,Credential Access,T1110,ssh\n",
        encoding="utf-8",
    )
    casino_path = tmp_path / "vendor" / "datasets" / "casinolimit" / "syslogs_labels.zip"
    casino_path.parent.mkdir(parents=True)
    with zipfile.ZipFile(casino_path, "w") as archive:
        archive.writestr(
            "system_labels/renard.json",
            json.dumps(
                {
                    "label-a": {"id": "label-a", "auditd_events": {"bastion": ["20"]}, "technique": "T1005: Data from Local System"},
                    "label-b": {"id": "label-b", "auditd_events": {"bastion": ["10"]}, "technique": "T1083: File and Directory Discovery"},
                }
            ),
        )
    mordor_path = tmp_path / "vendor" / "datasets" / "mordor" / "compound" / "SDWIN-test" / "metadata.yaml"
    mordor_path.parent.mkdir(parents=True)
    mordor_path.write_text(
        yaml.safe_dump(
            {
                "id": "SDWIN-test",
                "title": "Mordor compound scenario",
                "attack_mappings": [
                    {"technique": "T1552", "sub-technique": "001", "tactics": ["TA0006"]},
                    {"technique": "T1046", "tactics": ["TA0007"]},
                ],
            }
        ),
        encoding="utf-8",
    )

    events, stats = load_events([uwf_path, casino_path, mordor_path])
    prior, report = build_prior(events, stats=stats, alpha=0.0, min_support=1, global_fallback_weight=0.0)

    assert prior["transitions"]["T1595"]["T1110"]["support"] == 1
    assert prior["transitions"]["T1083"]["T1005"]["support"] == 1
    assert prior["transitions"]["T1552.001"]["T1046"]["support"] == 1
    assert report["source_counts"]["uwf-zeekdata24"]["events_used"] == 2
    assert report["source_counts"]["casinolimit"]["events_used"] == 2
    assert report["source_counts"]["mordor"]["events_used"] == 2
