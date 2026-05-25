from __future__ import annotations

from pathlib import Path

import pytest

from scripts.evaluation.charts import write_runtime_latency_chart


pytestmark = pytest.mark.unit


def test_runtime_latency_chart_writes_svg(tmp_path: Path) -> None:
    report = {
        "asset_count": 2,
        "summary": {"ok_assets": 1, "failed_assets": 1},
        "assets": [
            {
                "asset_id": "internal-portal",
                "ok": True,
                "orchestrator_apply_ms": 120.5,
                "route_visible_ms": 30.0,
            },
            {
                "asset_id": "finance-share",
                "ok": False,
                "orchestrator_apply_ms": 400.0,
                "route_visible_ms": None,
            },
        ],
    }
    path = tmp_path / "latency.svg"

    write_runtime_latency_chart(report, path)

    chart = path.read_text(encoding="utf-8")
    assert chart.startswith("<?xml") or chart.startswith("<svg")
    assert "Runtime Reveal Latency" in chart
