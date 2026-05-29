"""Matplotlib chart helpers for evaluation reports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def write_reveal_policy_chart(report: dict[str, Any], path: Path) -> None:
    """Write a 2×2 policy-comparison chart from `reveal_policy.py` output.

    Example:
        write_reveal_policy_chart(report, Path("/tmp/reveal_policy_report.svg")).
    """
    plt = _pyplot()
    policies = list(report.get("policies", {}).keys())
    labels = [_policy_label(policy) for policy in policies]
    controller = report.get("policies", {}).get("controller", {})
    n_policies = max(len(policies), 1)

    fig, axes = plt.subplots(
        2, 2,
        figsize=(14, max(8.0, 0.5 * n_policies + 4.5)),
    )
    ax_quality = axes[0][0]
    ax_gate = axes[0][1]
    ax_reject = axes[1][0]
    ax_prior = axes[1][1]

    # --- Panel 1: Policy quality (reasonable reveal vs unexpected action) ---
    quality_metrics = [
        ("reveal_correctness", "Reasonable reveal", "#14853d"),
        ("unexpected_reveal_action_rate", "Unexpected action", "#f59e0b"),
    ]
    y_positions = range(n_policies)
    bar_height = 0.26
    offsets = [-0.15, 0.15]
    for (key, label, color), offset in zip(quality_metrics, offsets):
        values = [float(report["policies"][p].get(key, 0.0) or 0.0) for p in policies]
        ax_quality.barh(
            [i + offset for i in y_positions], values,
            height=bar_height, label=label, color=color,
        )
    _format_policy_axis(ax_quality, y_positions, labels)
    ax_quality.set_xlim(0, 1)
    ax_quality.set_xlabel("Rate")
    ax_quality.set_title("Policy quality")
    ax_quality.grid(axis="x", color="#e5e7eb")
    ax_quality.legend(loc="lower right", fontsize=8)

    # --- Panel 2: Gate narrowing — how many eligible assets survive the hard gate ---
    # Shows what fraction of decision points leave 0 / 1 / 2+ assets for CF to rank.
    # "1 eligible" means the gate decided the outcome; CF had no room to act.
    bucket_rates = controller.get("gate_eligible_bucket_rates", {})
    zero_r = float(bucket_rates.get("zero", 0.0) or 0.0)
    one_r = float(bucket_rates.get("one", 0.0) or 0.0)
    two_r = float(bucket_rates.get("two_plus", 0.0) or 0.0)
    narrows = float(controller.get("gate_narrowing_rate", 0.0) or 0.0)
    ready_avg = float(controller.get("gate_ready_assets_before_gate_avg", 0.0) or 0.0)
    eligible_avg = float(controller.get("gate_eligible_assets_after_gate_avg", 0.0) or 0.0)
    dp_count = int(controller.get("gate_decision_point_count", 0) or 0)

    segments = [
        (zero_r, "#dc2626", "0 eligible — gate blocks all"),
        (one_r, "#f59e0b", "1 eligible — no CF room"),
        (two_r, "#14853d", "2+ eligible — CF active"),
    ]
    left = 0.0
    for val, color, seg_label in segments:
        ax_gate.barh([0], [val], left=[left], color=color, label=seg_label, height=0.4)
        if val > 0.04:
            ax_gate.text(
                left + val / 2, 0, f"{val:.0%}",
                ha="center", va="center", fontsize=9,
                color="white" if val > 0.12 else "black", fontweight="bold",
            )
        left += val
    ax_gate.set_yticks([0])
    ax_gate.set_yticklabels(["controller"])
    ax_gate.set_xlim(0, 1)
    ax_gate.set_xlabel("Fraction of decision points")
    ax_gate.set_title(
        f"Gate narrowing — {dp_count} decision points\n"
        f"avg: {ready_avg:.1f} ready → {eligible_avg:.1f} eligible  ({narrows:.0%} narrowed)"
    )
    ax_gate.grid(axis="x", color="#e5e7eb")
    ax_gate.legend(loc="lower right", fontsize=8)

    # --- Panel 3: Rejection reasons — why assets were filtered before CF scoring ---
    reason_rates = controller.get("rejection_reason_rates", {})
    if reason_rates:
        reasons = list(reason_rates.keys())
        r_values = [float(reason_rates[r] or 0.0) for r in reasons]
        short_labels = [_short_rejection_label(r) for r in reasons]
        y_pos = list(range(len(reasons)))
        ax_reject.barh(y_pos, r_values, color="#2563eb")
        ax_reject.set_yticks(y_pos)
        ax_reject.set_yticklabels(short_labels)
        ax_reject.invert_yaxis()
        x_max = max(r_values) * 1.3 if r_values else 1.0
        ax_reject.set_xlim(0, x_max)
        ax_reject.set_xlabel("Share of all gate rejections")
        ax_reject.set_title("Why assets were rejected before scoring (controller)")
        ax_reject.grid(axis="x", color="#e5e7eb")
        for i, v in enumerate(r_values):
            ax_reject.text(v, i, f" {v:.0%}", va="center", fontsize=8)
    else:
        ax_reject.text(
            0.5, 0.5, "No rejection data",
            ha="center", va="center", transform=ax_reject.transAxes,
        )
        ax_reject.set_title("Why assets were rejected before scoring (controller)")
        ax_reject.set_xticks([])
        ax_reject.set_yticks([])

    # --- Panel 4: Prior (CF) influence rate ---
    # Fraction of scenarios where the CF prior changed the reveal vs gate-only baseline.
    prior_rate = float(controller.get("prior_influence_rate", 0.0) or 0.0)
    influenced_count = int(controller.get("prior_influenced_scenario_count", 0) or 0)
    scenario_count = int(controller.get("scenario_count", 0) or 0)
    bar_vals = [prior_rate, 1.0 - prior_rate]
    bars = ax_prior.bar(
        ["CF changed\nresult", "Gate-only\nsufficient"],
        bar_vals,
        color=["#7c3aed", "#d1d5db"],
    )
    ax_prior.set_ylim(0, 1.2)
    ax_prior.set_ylabel("Fraction of scenarios")
    ax_prior.set_title(
        f"Prior (CF) influence rate\n"
        f"{influenced_count}/{scenario_count} scenarios where prior changed the reveal"
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
    top_k = int(report.get("top_k", 0) or 0)
    support_threshold = float(report.get("support_threshold", 0.0) or 0.0)
    prefix_count = int(metrics.get("prefix_count", 0) or 0)
    trace_count = int(report.get("trace_count", 0) or 0)

    summary_keys = [
        ("hit_rate_at_k", f"Hit@k={top_k}"),
        ("recall", "Recall"),
        ("precision", "Precision"),
        ("specificity", "Specificity"),
        ("accuracy", "Accuracy"),
    ]
    summary_values = [float(metrics.get(key, 0.0) or 0.0) for key, _ in summary_keys]
    summary_labels = [label for _, label in summary_keys]
    summary_colors = ["#7c3aed", "#14853d", "#2563eb", "#0891b2", "#64748b"]

    fig, axis = plt.subplots(1, 1, figsize=(7, 4.5))
    bars = axis.bar(summary_labels, summary_values, color=summary_colors)
    axis.set_ylim(0, 1.2)
    axis.set_title("Aggregate prediction quality\n(T1548.003 ≡ T1548 — technique-family level)")
    axis.set_ylabel("Rate")
    axis.tick_params(axis="x", rotation=20)
    axis.grid(axis="y", color="#e5e7eb")
    for bar, value in zip(bars, summary_values):
        axis.text(
            bar.get_x() + bar.get_width() / 2, value + 0.02,
            f"{value:.2f}", ha="center", va="bottom", fontsize=9,
        )

    fig.suptitle(
        f"ATT&CK Group CF Prior  ·  top_k={top_k}  support≥{support_threshold:.2f}"
        f"  ·  {trace_count} traces  {prefix_count} prefixes"
    )
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


def _short_rejection_label(reason: str) -> str:
    return {
        "dependency_not_satisfied": "Dep. not met",
        "already_revealed": "Already revealed",
        "not_ready_or_unavailable": "Not ready",
        "exposure_budget_reached": "Budget cap",
        "redundant_or_low_gain": "Low gain",
        "out_of_scope_or_no_signal": "No signal",
        "other": "Other",
    }.get(reason, reason.replace("_", " ").title())
