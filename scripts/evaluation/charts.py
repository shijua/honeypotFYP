"""Matplotlib chart helpers for evaluation reports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def write_reveal_policy_chart(report: dict[str, Any], path: Path) -> None:
    """Write a policy-comparison chart from `reveal_policy.py` output.

    Example:
        write_reveal_policy_chart(report, Path("/tmp/reveal_policy_report.svg")).
    """
    plt = _pyplot()
    policies = list(report.get("policies", {}).keys())
    labels = [_policy_label(policy) for policy in policies]
    metrics = [
        ("reveal_correctness", "Reasonable reveal", "#14853d"),
        ("unexpected_reveal_action_rate", "Unexpected action", "#f59e0b"),
    ]
    fig, axis = plt.subplots(
        1,
        1,
        figsize=(11, max(4.2, 0.5 * len(policies) + 1.6)),
    )
    y_positions = range(len(policies))
    bar_height = 0.26
    offsets = [-0.15, 0.15]
    for (key, label, color), offset in zip(metrics, offsets):
        values = [float(report["policies"][policy].get(key, 0.0) or 0.0) for policy in policies]
        axis.barh([index + offset for index in y_positions], values, height=bar_height, label=label, color=color)
    _format_policy_axis(axis, y_positions, labels)
    axis.set_xlim(0, 1)
    axis.set_xlabel("Rate")
    axis.set_title("Policy quality")
    axis.grid(axis="x", color="#e5e7eb")
    axis.legend(loc="lower right", fontsize=8)

    fig.suptitle(f"Reveal Policy Comparison - {int(report.get('scenario_count', 0) or 0)} scenarios")
    _save_chart(fig, path)


def write_prior_recommendation_chart(report: dict[str, Any], path: Path) -> None:
    """Write a prior-quality chart from `attack_group_prior_recommendation.py` output."""
    plt = _pyplot()
    metrics = report.get("metrics", {})
    summary_keys = [("recall", "Recall"), ("specificity", "Specificity"), ("accuracy", "Accuracy")]
    summary_values = [float(metrics.get(key, 0.0) or 0.0) for key, _label in summary_keys]
    rows = [
        row
        for row in metrics.get("source_breakdown", [])
        if isinstance(row, dict) and int(row.get("prefix_count", 0) or 0) > 0
    ]
    scenario_labels = [str(row.get("scenario_id", "scenario")) for row in rows]
    scenario_recall = [float(row.get("recall", 0.0) or 0.0) for row in rows]

    fig, (summary_axis, scenario_axis) = plt.subplots(
        1,
        2,
        figsize=(13, max(4.0, 0.42 * max(len(rows), 1) + 1.5)),
        gridspec_kw={"width_ratios": [1.3, 2.7]},
    )
    summary_axis.bar([label for _key, label in summary_keys], summary_values, color=["#14853d", "#2563eb", "#7c3aed"])
    summary_axis.set_ylim(0, 1)
    summary_axis.set_title("Prior metrics")
    summary_axis.set_ylabel("Rate")
    summary_axis.tick_params(axis="x", rotation=15)
    summary_axis.grid(axis="y", color="#e5e7eb")
    for index, value in enumerate(summary_values):
        summary_axis.text(index, value, f"{value:.2f}", ha="center", va="bottom", fontsize=8)

    y_positions = range(len(rows))
    scenario_axis.barh(list(y_positions), scenario_recall, color="#14853d")
    scenario_axis.set_yticks(list(y_positions))
    scenario_axis.set_yticklabels(scenario_labels)
    scenario_axis.invert_yaxis()
    scenario_axis.set_xlim(0, 1)
    scenario_axis.set_xlabel("Recall")
    scenario_axis.set_title("Scenario recall")
    scenario_axis.grid(axis="x", color="#e5e7eb")
    for index, value in enumerate(scenario_recall):
        scenario_axis.text(max(value, 0.01), index, f" {value:.2f}", va="center", fontsize=8)

    fig.suptitle(f"ATT&CK Group Prior Recommendation - {int(report.get('trace_count', 0) or 0)} traces")
    _save_chart(fig, path)


def write_runtime_latency_chart(report: dict[str, Any], path: Path) -> None:
    """Write a live latency chart from `runtime_latency.py` output."""
    plt = _pyplot()
    assets = [row for row in report.get("assets", []) if isinstance(row, dict)]
    labels = [str(row.get("asset_id", "asset")) for row in assets]
    apply_ms = [float(row.get("orchestrator_apply_ms", 0.0) or 0.0) for row in assets]
    route_ms = [float(row.get("route_visible_ms", 0.0) or 0.0) if row.get("route_visible_ms") is not None else 0.0 for row in assets]
    colors = ["#14853d" if row.get("ok") else "#dc2626" for row in assets]

    fig, (apply_axis, route_axis) = plt.subplots(
        1,
        2,
        figsize=(13, max(4.0, 0.42 * max(len(assets), 1) + 1.5)),
        gridspec_kw={"width_ratios": [1, 1]},
    )
    y_positions = range(len(assets))
    apply_axis.barh(list(y_positions), apply_ms, color=colors)
    apply_axis.set_yticks(list(y_positions))
    apply_axis.set_yticklabels(labels)
    apply_axis.invert_yaxis()
    apply_axis.set_xlabel("ms")
    apply_axis.set_title("Orchestrator apply")
    apply_axis.grid(axis="x", color="#e5e7eb")

    route_axis.barh(list(y_positions), route_ms, color=colors)
    route_axis.set_yticks(list(y_positions))
    route_axis.set_yticklabels([])
    route_axis.invert_yaxis()
    route_axis.set_xlabel("ms")
    route_axis.set_title("Route visible")
    route_axis.grid(axis="x", color="#e5e7eb")

    summary = report.get("summary", {})
    fig.suptitle(
        "Runtime Reveal Latency - "
        f"{int(summary.get('ok_assets', 0) or 0)} ok / {int(report.get('asset_count', 0) or 0)} assets"
    )
    _save_chart(fig, path)


def write_hypothesis_posterior_chart(report: dict[str, Any], path: Path) -> None:
    """Write posterior trajectory charts for hypothesis-testing replay rows."""
    policy = report.get("policies", {}).get("hypothesis-testing")
    if not isinstance(policy, dict):
        return
    rows = [
        row
        for row in policy.get("rows", [])
        if isinstance(row, dict) and row.get("posterior_trajectory")
    ]
    if not rows:
        return

    plt = _pyplot()
    row_count = len(rows)
    fig, axes = plt.subplots(
        row_count,
        1,
        figsize=(11, max(3.0, 2.3 * row_count)),
        squeeze=False,
    )
    for axis, row in zip([item[0] for item in axes], rows):
        trajectory = [item for item in row.get("posterior_trajectory", []) if isinstance(item, dict)]
        hypothesis_ids = sorted(
            {
                hypothesis_id
                for item in trajectory
                for hypothesis_id in (item.get("posterior") or {}).keys()
            }
        )
        steps = [int(item.get("step", index + 1) or index + 1) for index, item in enumerate(trajectory)]
        for hypothesis_id in hypothesis_ids:
            values = [
                float((item.get("posterior") or {}).get(hypothesis_id, 0.0) or 0.0)
                for item in trajectory
            ]
            axis.plot(steps, values, marker="o", linewidth=1.8, label=hypothesis_id)
        axis.set_ylim(0, 1)
        min_step = min(steps or [1])
        max_step = max(steps or [1])
        axis.set_xlim(min_step - 0.5, max_step + 0.5)
        axis.set_ylabel("P(h|E)")
        axis.set_title(str(row.get("scenario_id", "scenario")), loc="left", fontsize=10)
        axis.grid(axis="y", color="#e5e7eb")
        if len(hypothesis_ids) <= 6:
            axis.legend(loc="upper right", fontsize=7, ncols=min(3, max(1, len(hypothesis_ids))))
    axes[-1][0].set_xlabel("Decision point")
    fig.suptitle("Hypothesis Posterior Trajectory")
    _save_chart(fig, path)


def _pyplot():
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/matplotlib")
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams["svg.fonttype"] = "none"
    return plt


def _save_chart(fig: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(path, bbox_inches="tight")
    fig.clf()


def _format_policy_axis(axis: Any, y_positions: range, labels: list[str]) -> None:
    axis.set_yticks(list(y_positions))
    axis.set_yticklabels(labels)
    axis.invert_yaxis()


def _policy_label(policy: str) -> str:
    return policy.replace("-", " ").title()
