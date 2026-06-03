from __future__ import annotations

from pathlib import Path

import pytest

from scripts.evaluation.charts import write_runtime_latency_chart


pytestmark = pytest.mark.unit


def test_runtime_latency_chart_writes_svg(tmp_path: Path) -> None:
    report = {
        "asset_count": 2,
        "sample_count": 4,
        "run_count": 2,
        "summary": {"ok_samples": 3, "failed_samples": 1},
        "class_summary": {
            "warm": {"ok_samples": 3, "failed_samples": 0},
            "cold": {"ok_samples": 1, "failed_samples": 1},
        },
        "mode_summary": {
            "direct": {"ok_samples": 2, "failed_samples": 1},
            "prewarmed": {"ok_samples": 1, "failed_samples": 0},
        },
        "asset_summary": [
            {
                "asset_id": "internal-portal",
                "reveal_mode": "direct",
                "latency_class": "warm",
                "ok_samples": 2,
                "failed_samples": 0,
                "apply_p50_ms": 120.5,
                "apply_p95_ms": 130.0,
            },
            {
                "asset_id": "internal-portal",
                "reveal_mode": "prewarmed",
                "latency_class": "warm",
                "ok_samples": 1,
                "failed_samples": 0,
                "apply_p50_ms": 35.0,
                "apply_p95_ms": 35.0,
            },
            {
                "asset_id": "admin-jumpbox",
                "reveal_mode": "direct",
                "latency_class": "cold",
                "ok_samples": 1,
                "failed_samples": 1,
                "apply_p50_ms": 400.0,
                "apply_p95_ms": 450.0,
            },
        ],
        "assets": [
            {
                "asset_id": "internal-portal",
                "reveal_mode": "direct",
                "latency_class": "warm",
                "ok": True,
                "orchestrator_apply_ms": 120.5,
                "route_state_ready": True,
            },
            {
                "asset_id": "admin-jumpbox",
                "reveal_mode": "direct",
                "latency_class": "cold",
                "ok": False,
                "orchestrator_apply_ms": 400.0,
                "route_state_ready": False,
            },
        ],
    }
    path = tmp_path / "latency.svg"

    write_runtime_latency_chart(report, path)

    chart = path.read_text(encoding="utf-8")
    assert chart.startswith("<?xml") or chart.startswith("<svg")
    assert "Runtime Reveal Apply Latency" in chart

    assert "internal-portal (prewarmed)" in chart
