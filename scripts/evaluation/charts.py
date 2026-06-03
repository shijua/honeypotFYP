"""Matplotlib chart helpers for evaluation reports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def write_reveal_policy_chart(report: dict[str, Any], path: Path) -> None:
    """Write a compact policy-comparison chart from `reveal_policy.py` output.

    Example:
        write_reveal_policy_chart(report, Path("/tmp/reveal_policy_report.svg")).
    """
    plt = _pyplot()
    policies = list(report.get("policies", {}).keys())
    labels = [_policy_label(policy) for policy in policies]
    controller = report.get("policies", {}).get("controller", {})
    n_policies = max(len(policies), 1)

    fig, axes = plt.subplots(
        1, 2,
        figsize=(13, max(4.2, 0.48 * n_policies + 2.6)),
    )
    ax_quality = axes[0]
    ax_prior = axes[1]

    # --- Panel 1: main scenarios use anchor correctness; broad regression
    # fixtures without anchors fall back to scenario-supported reveal rate.
    has_anchor_steps = any(
        int(report.get("policies", {}).get(policy, {}).get("anchor_step_count", 0) or 0) > 0
        for policy in policies
    )
    primary_metric = "anchor_step_correctness_rate" if has_anchor_steps else "reveal_correctness"
    primary_label = "Anchor correctness" if has_anchor_steps else "Supported reveal"
    primary_title = "Anchor decision correctness" if has_anchor_steps else "Scenario-supported reveal rate"
    quality_metrics = [
        (primary_metric, primary_label, "#14853d"),
        ("useful_evidence_per_reveal", "Useful response", "#2563eb"),
        ("irrelevant_reveal_rate", "Unsupported reveal", "#f59e0b"),
        ("hidden_violation_rate", "Forbidden reveal", "#dc2626"),
    ]
    y_positions = range(n_policies)
    bar_height = 0.18
    offsets = [-0.3, -0.1, 0.1, 0.3]
    for (key, label, color), offset in zip(quality_metrics, offsets):
        values = [float(report["policies"][p].get(key, 0.0) or 0.0) for p in policies]
        ax_quality.barh(
            [i + offset for i in y_positions], values,
            height=bar_height, label=label, color=color,
        )
    _format_policy_axis(ax_quality, y_positions, labels)
    ax_quality.set_xlim(0, 1)
    ax_quality.set_xlabel("Rate")
    ax_quality.set_title(primary_title)
    ax_quality.grid(axis="x", color="#e5e7eb")
    ax_quality.legend(loc="upper right", fontsize=8)

    # --- Panel 2: Prior (CF) influence rate ---
    # Fraction of decision steps where the CF prior changed the reveal vs gate-only.
    prior_rate = float(controller.get("prior_influence_rate", 0.0) or 0.0)
    influenced_count = int(controller.get("prior_influenced_step_count", 0) or 0)
    comparison_count = int(controller.get("prior_comparison_step_count", 0) or 0)
    bar_vals = [prior_rate, 1.0 - prior_rate]
    bars = ax_prior.bar(
        ["CF changed\nresult", "Gate-only\nsufficient"],
        bar_vals,
        color=["#7c3aed", "#d1d5db"],
    )
    ax_prior.set_ylim(0, 1.2)
    ax_prior.set_ylabel("Fraction of decision steps")
    ax_prior.set_title(
        f"Prior (CF) influence rate\n"
        f"{influenced_count}/{comparison_count} steps where prior changed the reveal"
    )
    ax_prior.grid(axis="y", color="#e5e7eb")
    for bar, val in zip(bars, bar_vals):
        ax_prior.text(
            bar.get_x() + bar.get_width() / 2, val + 0.02,
            f"{val:.0%}", ha="center", va="bottom", fontsize=11, fontweight="bold",
        )

    fig.suptitle(f"Reveal Policy Comparison — {int(report.get('scenario_count', 0) or 0)} scenarios")
    _save_chart(fig, path)


def write_prior_recommendation_chart(report: dict[str, Any], path: Path) -> None:
    """Write a prior-quality chart from `attack_group_prior_recommendation.py` output."""
    plt = _pyplot()
    metrics = report.get("metrics", {})
    k_sweep = [row for row in report.get("k_sweep", []) if isinstance(row, dict)]
    top_k = int(report.get("top_k", 0) or 0)
    support_threshold = float(report.get("support_threshold", 0.0) or 0.0)
    prefix_count = int(metrics.get("prefix_count", 0) or 0)
    trace_count = int(report.get("trace_count", 0) or 0)

    fig, axis = plt.subplots(1, 1, figsize=(8.6, 4.8))
    if k_sweep:
        x_values = [int(row.get("top_k", 0) or 0) for row in k_sweep]
        series = [
            ("hit_rate_at_k", "Hit", "#7c3aed", "o"),
            ("recall", "Recall", "#14853d", "s"),
            ("precision", "Precision", "#2563eb", "^"),
            ("mrr", "MRR", "#f59e0b", "D"),
        ]
        for key, label, color, marker in series:
            y_values = [float(row.get(key, 0.0) or 0.0) for row in k_sweep]
            axis.plot(x_values, y_values, marker=marker, linewidth=2, color=color, label=label)
            for x_val, y_val in zip(x_values, y_values):
                axis.text(x_val, y_val + 0.025, f"{y_val:.2f}", ha="center", fontsize=8)
        axis.set_xticks(x_values)
        axis.legend(loc="upper left", bbox_to_anchor=(1.01, 1.0), fontsize=8, borderaxespad=0.0)
    else:
        summary_keys = [
            ("hit_rate_at_k", f"Hit@K={top_k}"),
            ("recall", "Recall"),
            ("precision", "Precision"),
            ("mrr", "MRR"),
        ]
        summary_values = [float(metrics.get(key, 0.0) or 0.0) for key, _ in summary_keys]
        summary_labels = [label for _, label in summary_keys]
        bars = axis.bar(summary_labels, summary_values, color=["#7c3aed", "#14853d", "#2563eb", "#f59e0b"])
        for bar, value in zip(bars, summary_values):
            axis.text(bar.get_x() + bar.get_width() / 2, value + 0.02, f"{value:.2f}", ha="center", va="bottom", fontsize=9)
        axis.tick_params(axis="x", rotation=20)
    axis.set_ylim(0, 1.2)
    axis.set_title(_prior_chart_title(report))
    axis.set_xlabel("Similar ATT&CK groups used by prior (K)")
    axis.set_ylabel("Rate")
    axis.grid(axis="y", color="#e5e7eb")
    diagnostics = report.get("dataset_diagnostics", {})
    if isinstance(diagnostics, dict) and diagnostics:
        concentration = diagnostics.get("concentration", {})
        overlap = diagnostics.get("prior_overlap", {})
        unique_count = int(diagnostics.get("unique_technique_family_count", 0) or 0)
        top3_share = float(concentration.get("top_3_share", 0.0) or 0.0) if isinstance(concentration, dict) else 0.0
        overlap_rate = (
            float(overlap.get("dataset_family_covered_by_prior_rate", 0.0) or 0.0)
            if isinstance(overlap, dict)
            else 0.0
        )
        axis.text(
            0.5,
            -0.23,
            f"{trace_count} traces / {prefix_count} prefixes · "
            f"{unique_count} unique technique families · "
            f"top-3 share {top3_share:.2f} · prior overlap {overlap_rate:.2f}",
            transform=axis.transAxes,
            ha="center",
            va="top",
            fontsize=8,
            color="#475569",
        )

    # fig.suptitle(
    #     f"ATT&CK Group CF Prior  ·  neighbor K={top_k}  support≥{support_threshold:.2f}"
    #     f"  ·  {trace_count} traces  {prefix_count} prefixes"
    # )
    fig.subplots_adjust(right=0.82)
    _save_chart(fig, path)


def write_runtime_latency_chart(report: dict[str, Any], path: Path) -> None:
    """Write a live latency chart from `runtime_latency.py` output."""
    rows = [row for row in report.get("asset_summary", []) if isinstance(row, dict)]
    if not rows:
        rows = [row for row in report.get("assets", []) if isinstance(row, dict)]
    class_summary = report.get("class_summary", {})
    mode_summary = report.get("mode_summary", {})
    warm_count = int(class_summary.get("warm", {}).get("ok_samples", class_summary.get("warm", {}).get("ok_assets", 0)) or 0)
    cold_count = int(class_summary.get("cold", {}).get("ok_samples", class_summary.get("cold", {}).get("ok_assets", 0)) or 0)
    prewarmed_count = int(mode_summary.get("prewarmed", {}).get("ok_samples", 0) or 0)
    _write_runtime_latency_rows_chart(
        report,
        rows,
        path,
        title="Runtime Reveal Apply Latency",
        extra_title=f"  ·  warm {warm_count}  cold {cold_count}  prewarmed {prewarmed_count}",
    )


def _write_runtime_latency_rows_chart(
    report: dict[str, Any],
    rows: list[dict[str, Any]],
    path: Path,
    *,
    title: str,
    extra_title: str = "",
) -> None:
    """Write one latency bar chart for already summarized rows."""
    plt = _pyplot()
    rows = sorted(
        rows,
        key=lambda row: (
            row.get("latency_class") == "cold",
            str(row.get("asset_id", "asset")),
            row.get("reveal_mode") != "direct",
        ),
    )
    labels = [
        str(row.get("asset_id", "asset"))
        if str(row.get("reveal_mode", "direct")) == "direct"
        else f"{row.get('asset_id', 'asset')} ({row.get('reveal_mode')})"
        for row in rows
    ]
    apply_p50_ms = [
        float(row.get("apply_p50_ms", row.get("orchestrator_apply_ms", 0.0)) or 0.0)
        for row in rows
    ]
    apply_p95_ms = [
        float(row.get("apply_p95_ms", row.get("orchestrator_apply_ms", 0.0)) or 0.0)
        for row in rows
    ]
    failed_rows = [not row.get("ok", int(row.get("failed_samples", 0) or 0) == 0) for row in rows]

    fig, axis = plt.subplots(
        1,
        1,
        figsize=(10.8, max(4.2, 0.54 * max(len(rows), 1) + 1.5)),
    )
    y_positions = list(range(len(rows)))
    p50_colors = ["#dc2626" if failed else "#2563eb" for failed in failed_rows]
    p95_colors = ["#991b1b" if failed else "#f59e0b" for failed in failed_rows]
    p50_bars = axis.barh([position - 0.18 for position in y_positions], apply_p50_ms, height=0.34, color=p50_colors, label="p50")
    p95_bars = axis.barh([position + 0.18 for position in y_positions], apply_p95_ms, height=0.34, color=p95_colors, label="p95")
    for bars, values in ((p50_bars, apply_p50_ms), (p95_bars, apply_p95_ms)):
        for bar, value in zip(bars, values):
            axis.text(
                bar.get_width(),
                bar.get_y() + bar.get_height() / 2,
                f"  {value:.0f}",
                va="center",
                fontsize=8,
            )
    axis.set_yticks(y_positions)
    axis.set_yticklabels(labels)
    axis.invert_yaxis()
    axis.set_xlabel("orchestrator apply latency (ms)")
    axis.set_title("Runtime Reveal Apply Latency by Asset")
    axis.legend(loc="upper right")
    axis.grid(axis="x", color="#e5e7eb")

    ok_count = sum(int(row.get("ok_samples", 1 if row.get("ok") else 0) or 0) for row in rows)
    sample_count = sum(int(row.get("sample_count", 1) or 0) for row in rows)
    # fig.suptitle(
    #     f"{title} - "
    #     f"{ok_count} ok / {sample_count} samples"
    #     f"{extra_title}"
    #     f"  ·  runs {int(report.get('run_count', 1) or 1)}"
    # )
    _save_chart(fig, path)


def _runtime_latency_color(row: dict[str, Any]) -> str:
    """Color latency bars by warm/cold path, with failed assets highlighted."""
    if not row.get("ok"):
        return "#dc2626"
    if row.get("reveal_mode") == "prewarmed":
        return "#2563eb"
    if row.get("latency_class") == "cold":
        return "#f59e0b"
    return "#14853d"


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


def _prior_chart_title(report: dict[str, Any]) -> str:
    if isinstance(report.get("dataset_diagnostics"), dict):
        sources = report.get("dataset_sources")
        if isinstance(sources, list) and len(sources) == 1 and isinstance(sources[0], str):
            source_label = "CasinoLimit" if sources[0] == "casinolimit" else sources[0].replace("_", " ").replace("-", " ").title()
            return f"{source_label} prior candidate quality by similar-group K"
        return "Public dataset prior candidate quality by similar-group K"
    return "Scenario prior candidate quality by similar-group K"
