#!/usr/bin/env python3
"""Measure live orchestrator and asset-gateway latency for internal asset unlocks.

Run this only after the compose stack is up. It calls private control-plane APIs
through the control-plane containers' bridge IPs, so the measurement excludes the
startup cost of temporary curl containers.

Example:
    python scripts/evaluation/runtime_latency.py --assets internal-portal,finance-share
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any
import sys
ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from libs.common.json_store import JsonFileStore
from libs.common.json_utils import read_json_value
from scripts.evaluation.charts import write_runtime_latency_chart


DEFAULT_ASSET_GATEWAY_PORTS = "18080,19418,13306,16379,18081,12121,12222,12323,2525,18082,18443,18085,1445,11433,12122,19999,10222"


def main() -> int:
    """Measure live unlock latency and print a JSON report.

    Example:
        python scripts/evaluation/runtime_latency.py --assets internal-portal,finance-share

    Output shape:
        {"binding_resolve_ms": 12.4, "assets": [{"asset_id": "internal-portal", ...}]}
    """
    parser = argparse.ArgumentParser(description="Measure live internal asset reveal latency.")
    parser.add_argument("--project-name", default=os.environ.get("PROJECT_NAME", "honeynet"))
    parser.add_argument("--attacker-key", default=os.environ.get("CLIENT_TARGET_HOST", os.environ.get("HOST_BIND_ADDRESS", "127.0.0.1")))
    parser.add_argument("--catalog", default="data/assets/catalog.json")
    parser.add_argument("--state-dir", default="data/runtime")
    parser.add_argument("--assets", default="", help="Comma-separated asset ids. Defaults to fixed-port Docker assets.")
    parser.add_argument("--route-timeout", type=float, default=10.0)
    parser.add_argument("--runs", type=int, default=1, help="Number of fresh bindings to sample for each asset.")
    parser.add_argument("--run-id", default="", help="Optional stable id used to suffix generated latency attacker keys.")
    parser.add_argument(
        "--keep-latency-samples",
        action="store_true",
        help="Do not remove generated latency bindings/containers between runs.",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    catalog = read_json_value(Path(args.catalog), [])
    asset_ids = _selected_asset_ids(catalog, explicit=args.assets)
    latency_classes = _asset_latency_classes(catalog)
    if args.dry_run:
        print(
            json.dumps(
                {
                    "schema_version": "v1",
                    "attacker_key": args.attacker_key,
                    "run_count": args.runs,
                    "assets": [
                        {"asset_id": asset_id, "latency_class": latency_classes.get(asset_id, "cold")}
                        for asset_id in asset_ids
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    run_id = args.run_id.strip() or str(int(time.time() * 1000))
    results: list[dict[str, Any]] = []
    binding_samples: list[dict[str, Any]] = []
    cleanup_samples: list[dict[str, Any]] = []
    cleanup_enabled = not args.keep_latency_samples
    if cleanup_enabled:
        _ensure_runtime_state_writable(Path(args.state_dir))
    for run_index in range(1, args.runs + 1):
        if cleanup_enabled:
            cleanup_samples.append(
                _cleanup_generated_latency_samples(
                    project_name=args.project_name,
                    state_dir=Path(args.state_dir),
                    attacker_key_prefix=f"{args.attacker_key}-latency-",
                    phase=f"before-run-{run_index}",
                )
            )
        for asset_id in asset_ids:
            attacker_key = (
                args.attacker_key
                if args.runs == 1 and len(asset_ids) == 1
                else f"{args.attacker_key}-latency-{run_id}-direct-{run_index}-{asset_id}"
            )
            binding, binding_latency = _resolve_binding(args.project_name, attacker_key)
            binding_samples.append(
                {
                    "run_index": run_index,
                    "reveal_mode": "direct",
                    "asset_id": asset_id,
                    "attacker_key": attacker_key,
                    "binding_id": binding["binding_id"],
                    "binding_resolve_ms": binding_latency,
                }
            )
            results.append(
                _measure_asset(
                    project_name=args.project_name,
                    run_index=run_index,
                    reveal_mode="direct",
                    binding_id=binding["binding_id"],
                    attacker_key=attacker_key,
                    asset_id=asset_id,
                    latency_class=latency_classes.get(asset_id, "cold"),
                    state_dir=Path(args.state_dir),
                    route_timeout=args.route_timeout,
                )
            )
            if cleanup_enabled and _is_generated_latency_key(attacker_key, args.attacker_key):
                cleanup_samples.append(
                    _cleanup_binding_sample(
                        project_name=args.project_name,
                        state_dir=Path(args.state_dir),
                        binding_id=str(binding["binding_id"]),
                        attacker_key=attacker_key,
                        phase=f"after-direct-{run_index}-{asset_id}",
                    )
                )
            if latency_classes.get(asset_id, "cold") != "warm":
                continue
            prewarm_attacker_key = f"{args.attacker_key}-latency-{run_id}-prewarmed-{run_index}-{asset_id}"
            prewarm_binding, prewarm_binding_latency = _resolve_binding(args.project_name, prewarm_attacker_key)
            prewarm_response, prewarm_ms = _prewarm_assets(
                project_name=args.project_name,
                binding_id=prewarm_binding["binding_id"],
                asset_ids=[asset_id],
            )
            binding_samples.append(
                {
                    "run_index": run_index,
                    "reveal_mode": "prewarmed",
                    "asset_id": asset_id,
                    "attacker_key": prewarm_attacker_key,
                    "binding_id": prewarm_binding["binding_id"],
                    "binding_resolve_ms": prewarm_binding_latency,
                    "prewarm_apply_ms": prewarm_ms,
                    "warmed_asset_ids": prewarm_response.get("warmed_asset_ids", []),
                    "failed_asset_ids": prewarm_response.get("failed_asset_ids", []),
                }
            )
            results.append(
                _measure_asset(
                    project_name=args.project_name,
                    run_index=run_index,
                    reveal_mode="prewarmed",
                    binding_id=prewarm_binding["binding_id"],
                    attacker_key=prewarm_attacker_key,
                    asset_id=asset_id,
                    latency_class="warm",
                    state_dir=Path(args.state_dir),
                    route_timeout=args.route_timeout,
                )
            )
            if cleanup_enabled:
                cleanup_samples.append(
                    _cleanup_binding_sample(
                        project_name=args.project_name,
                        state_dir=Path(args.state_dir),
                        binding_id=str(prewarm_binding["binding_id"]),
                        attacker_key=prewarm_attacker_key,
                        phase=f"after-prewarmed-{run_index}-{asset_id}",
                    )
                )

    report = {
        "schema_version": "v1",
        "attacker_key": args.attacker_key,
        "requested_attacker_key": args.attacker_key,
        "run_id": run_id,
        "run_count": args.runs,
        "asset_count": len(asset_ids),
        "sample_count": len(results),
        "binding_id": binding_samples[0]["binding_id"] if binding_samples else None,
        "binding_resolve_ms": binding_samples[0]["binding_resolve_ms"] if binding_samples else None,
        "binding_samples": binding_samples,
        "cleanup_enabled": cleanup_enabled,
        "cleanup_samples": cleanup_samples,
        "assets": results,
        "asset_summary": _latency_summary_by_asset(results),
        "summary": _latency_summary(results),
        "class_summary": _latency_summary_by_class(results),
        "mode_summary": _latency_summary_by_mode(results),
        "path_summary": _latency_summary_by_path(results),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_runtime_latency_chart(report, args.output.with_suffix(".png"))
    else:
        print(text)
    return 0 if all(item["ok"] for item in results) else 1


def _selected_asset_ids(catalog: list[Any], *, explicit: str) -> list[str]:
    """Return explicit assets or fixed-port Docker assets from the catalog.

    Without `--assets`, the probe only measures internal Docker assets whose
    requested host ports are served by the shared asset-gateway. That keeps this
    script aligned with the fixed-port MVP surface instead of later/high-interaction assets.

    Example:
        explicit="internal-portal,finance-share" -> ["internal-portal", "finance-share"]
    """
    if explicit.strip():
        return [item.strip() for item in explicit.split(",") if item.strip()]
    gateway_ports = {int(item) for item in os.environ.get("ASSET_GATEWAY_PORTS", DEFAULT_ASSET_GATEWAY_PORTS).split(",") if item.strip().isdigit()}
    selected: list[str] = []
    for asset in catalog:
        if not isinstance(asset, dict) or asset.get("exposure_type") != "internal":
            continue
        runtime = asset.get("default_settings", {}).get("runtime", {})
        if not isinstance(runtime, dict) or runtime.get("backend") != "docker":
            continue
        mappings = runtime.get("port_mappings", [])
        if not isinstance(mappings, list):
            continue
        if any(int(item.get("requested_host_port", item.get("container_port", 0))) in gateway_ports for item in mappings if isinstance(item, dict)):
            selected.append(str(asset["asset_id"]))
    return selected


def _asset_latency_classes(catalog: list[Any]) -> dict[str, str]:
    """Return catalog-owned warm/cold labels for latency reporting.

    The label is descriptive only: the measurement still calls the same
    orchestration API. Splitting the report prevents warm route refreshes and
    cold container starts from being averaged into one misleading number.
    """
    classes: dict[str, str] = {}
    for asset in catalog:
        if not isinstance(asset, dict):
            continue
        runtime = asset.get("default_settings", {}).get("runtime", {})
        if not isinstance(runtime, dict):
            continue
        classes[str(asset.get("asset_id"))] = "warm" if runtime.get("warm_standby") is True else "cold"
    return classes


def _resolve_binding(project_name: str, attacker_key: str) -> tuple[dict[str, Any], float]:
    """Resolve/create the binding and return `(binding_json, elapsed_ms)`.

    This measures the control-plane binding lookup separately from asset reveal
    latency, so the final report can distinguish profile/binding overhead from
    runtime container and route setup.
    """
    payload = {"attacker_key": attacker_key, "protocol": "tcp"}
    url = f"{_container_base_url(project_name, 'binding-service', 8001)}/v1/bindings/resolve"
    started = time.perf_counter()
    response = _post_json(url, payload)
    return response, _elapsed_ms(started)


def _prewarm_assets(project_name: str, binding_id: str, asset_ids: list[str]) -> tuple[dict[str, Any], float]:
    """Start hidden warm-standby backends and return `(response, elapsed_ms)`."""
    payload = {"binding_id": binding_id, "asset_ids": asset_ids}
    url = f"{_container_base_url(project_name, 'orchestrator', 8005)}/v1/orchestration/prewarm"
    started = time.perf_counter()
    response = _post_json(url, payload)
    return response, _elapsed_ms(started)


def _measure_asset(
    *,
    project_name: str,
    run_index: int,
    reveal_mode: str,
    binding_id: str,
    attacker_key: str,
    asset_id: str,
    latency_class: str,
    state_dir: Path,
    route_timeout: float,
) -> dict[str, Any]:
    """Measure one asset reveal from controller action to route-state readiness.

    Returns:
        `orchestrator_apply_ms`: API time for `/v1/orchestration/apply`.
        `route_state_ready`: whether `asset_gateway_routes.json` contains the
        attacker/asset route consumed by asset-gateway within the timeout.
    """
    payload = {
        "binding_id": binding_id,
        "actions": [
            {
                "action_type": "unlock",
                "binding_id": binding_id,
                "asset_id": asset_id,
                "reason": "latency evaluation unlock",
            }
        ],
    }
    url = f"{_container_base_url(project_name, 'orchestrator', 8005)}/v1/orchestration/apply"
    # Time the orchestrator API only: Docker start/apply work should be inside this window.
    started = time.perf_counter()
    response = _post_json(url, payload)
    apply_ms = _elapsed_ms(started)
    # Route-state readiness is a pass/fail guard, not an attacker-visible latency metric.
    route_state_ready = _wait_for_route(state_dir / "asset_gateway_routes.json", attacker_key=attacker_key, asset_id=asset_id, timeout=route_timeout)
    runtime_event = next((item for item in response.get("runtime_events", []) if item.get("asset_id") == asset_id), {})
    return {
        "run_index": run_index,
        "reveal_mode": reveal_mode,
        "attacker_key": attacker_key,
        "binding_id": binding_id,
        "asset_id": asset_id,
        "latency_class": latency_class,
        "warm_standby": latency_class == "warm",
        "ok": runtime_event.get("status") == "running" and route_state_ready,
        "orchestrator_apply_ms": apply_ms,
        "route_state_ready": route_state_ready,
        "runtime_status": runtime_event.get("status", "missing"),
        "runtime_backend": runtime_event.get("settings", {}).get("runtime_backend"),
        "route_updates": response.get("route_updates", []),
    }


def _is_generated_latency_key(attacker_key: str, requested_attacker_key: str) -> bool:
    """Return True for synthetic attacker keys created by this latency script."""
    return attacker_key.startswith(f"{requested_attacker_key}-latency-")


def _ensure_runtime_state_writable(state_dir: Path) -> None:
    """Fail early with a useful message when runtime state is not user-writable."""
    lock_paths = [
        state_dir / ".bindings.json.lock",
        state_dir / ".asset_runtime.json.lock",
        state_dir / ".asset_gateway_routes.json.lock",
        state_dir / ".gateway_routes.json.lock",
    ]
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        for lock_path in lock_paths:
            with lock_path.open("a+", encoding="utf-8"):
                pass
    except PermissionError as exc:
        raise SystemExit(
            "runtime latency cleanup cannot write data/runtime lock files. "
            "Stop the stack if it is running, then fix ownership with:\n"
            f"  sudo chown -R $USER:$USER {state_dir}\n"
            f"permission error: {exc}"
        ) from exc


def _cleanup_generated_latency_samples(
    *,
    project_name: str,
    state_dir: Path,
    attacker_key_prefix: str,
    phase: str,
) -> dict[str, Any]:
    """Remove previous generated latency bindings before the next sample run."""
    bindings = read_json_value(state_dir / "bindings.json", {"records": []}).get("records", [])
    stale = [
        item
        for item in bindings
        if isinstance(item, dict) and str(item.get("attacker_key", "")).startswith(attacker_key_prefix)
    ]
    binding_ids = [str(item.get("binding_id")) for item in stale if item.get("binding_id")]
    for binding_id in binding_ids:
        _remove_docker_containers_for_binding(project_name, binding_id)
    _remove_runtime_state_for_bindings(state_dir, set(binding_ids), attacker_key_prefix=attacker_key_prefix)
    return {
        "phase": phase,
        "binding_count": len(binding_ids),
        "binding_ids": binding_ids,
    }


def _cleanup_binding_sample(
    *,
    project_name: str,
    state_dir: Path,
    binding_id: str,
    attacker_key: str,
    phase: str,
) -> dict[str, Any]:
    """Remove one generated latency binding after its timing sample is recorded."""
    _remove_docker_containers_for_binding(project_name, binding_id)
    _remove_runtime_state_for_bindings(state_dir, {binding_id}, attacker_key_prefix=attacker_key)
    return {
        "phase": phase,
        "binding_count": 1,
        "binding_ids": [binding_id],
    }


def _remove_docker_containers_for_binding(project_name: str, binding_id: str) -> None:
    """Remove dynamic runtime containers for one binding without touching compose."""
    if not binding_id:
        return
    result = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            "label=honeynet.mvp=true",
            "--filter",
            f"label=honeynet.binding_id={binding_id}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    container_ids = [item for item in result.stdout.splitlines() if item.strip()]
    if not container_ids:
        return
    subprocess.run(
        ["docker", "rm", "-f", *container_ids],
        capture_output=True,
        text=True,
        check=False,
    )


def _remove_runtime_state_for_bindings(
    state_dir: Path,
    binding_ids: set[str],
    *,
    attacker_key_prefix: str,
) -> None:
    """Drop latency-only binding/runtime/route records from file-backed state."""
    if not binding_ids and not attacker_key_prefix:
        return
    _filter_json_list(
        state_dir / "bindings.json",
        default={"records": []},
        list_key="records",
        keep=lambda item: (
            str(item.get("binding_id", "")) not in binding_ids
            and not str(item.get("attacker_key", "")).startswith(attacker_key_prefix)
        ),
    )
    _filter_json_list(
        state_dir / "asset_runtime.json",
        default={"records": []},
        list_key="records",
        keep=lambda item: str(item.get("binding_id", "")) not in binding_ids,
    )
    for filename in ("asset_gateway_routes.json", "gateway_routes.json"):
        _filter_json_list(
            state_dir / filename,
            default={"routes": []},
            list_key="routes",
            keep=lambda item: (
                str(item.get("binding_id", "")) not in binding_ids
                and not str(item.get("attacker_key", "")).startswith(attacker_key_prefix)
            ),
        )


def _filter_json_list(
    path: Path,
    *,
    default: dict[str, Any],
    list_key: str,
    keep,
) -> None:
    """Atomically filter a top-level JSON list when the file exists."""
    store = JsonFileStore(path, default)

    def mutator(payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        items = payload.get(list_key)
        if not isinstance(items, list):
            payload[list_key] = []
            return
        payload[list_key] = [
            item for item in items if not isinstance(item, dict) or keep(item)
        ]

    store.update(mutator)


def _wait_for_route(path: Path, *, attacker_key: str, asset_id: str, timeout: float) -> bool:
    """Return whether the route table contains the expected route.

    Example:
        (attacker_key="146.169.44.23", asset_id="finance-share") -> True
    """
    started = time.perf_counter()
    while time.perf_counter() - started <= timeout:
        routes = read_json_value(path, {"routes": []}).get("routes", [])
        if any(item.get("attacker_key") == attacker_key and item.get("asset_id") == asset_id for item in routes if isinstance(item, dict)):
            return True
        time.sleep(0.1)
    return False


def _container_base_url(project_name: str, service_name: str, port: int) -> str:
    """Return a host-reachable URL for a compose service container.

    Example:
        _container_base_url("honeynet", "orchestrator", 8005) -> "http://192.168.64.7:8005"
    """
    container_name = f"{project_name}_{service_name}_1"
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            container_name,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    addresses = [item for item in result.stdout.split() if item]
    if not addresses:
        raise RuntimeError(f"container has no bridge IP: {container_name}")
    return f"http://{addresses[0]}:{port}"


def _post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST JSON and decode an object response.

    Example:
        _post_json("http://192.168.64.7:8005/v1/orchestration/apply", {"actions": [...]})
        -> {"runtime_events": [...], "route_updates": [...]}
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def _elapsed_ms(started: float) -> float:
    """Return milliseconds since a `time.perf_counter()` snapshot.

    Example:
        started=time.perf_counter(); ...; _elapsed_ms(started) -> 37.214
    """
    return round((time.perf_counter() - started) * 1000, 3)


def _latency_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Return ok/failed counts plus min/p50/p95/max apply latency.

    Example:
        [{"ok": True, "orchestrator_apply_ms": 10.0}] -> {"ok_assets": 1, ...}
    """
    summary: dict[str, Any] = {
        "sample_count": len(results),
        "ok_samples": sum(1 for item in results if item["ok"]),
        "failed_samples": sum(1 for item in results if not item["ok"]),
    }
    # Backwards-compatible aliases for older chart/report consumers.
    summary["ok_assets"] = summary["ok_samples"]
    summary["failed_assets"] = summary["failed_samples"]
    apply_values = sorted(float(item["orchestrator_apply_ms"]) for item in results if isinstance(item.get("orchestrator_apply_ms"), (int, float)))
    if apply_values:
        summary.update(_latency_distribution("apply", apply_values))
    return summary


def _latency_summary_by_class(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return latency summaries split into catalog warm and cold paths."""
    grouped = {
        "warm": [item for item in results if item.get("latency_class") == "warm"],
        "cold": [item for item in results if item.get("latency_class") == "cold"],
    }
    return {name: _latency_summary(items) for name, items in grouped.items() if items}


def _latency_summary_by_mode(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return latency summaries split by reveal mode."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        grouped.setdefault(str(item.get("reveal_mode", "direct")), []).append(item)
    return {name: _latency_summary(items) for name, items in sorted(grouped.items())}


def _latency_summary_by_path(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return summaries for the report's main warm/cold comparison paths."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        key = f"{item.get('latency_class', 'cold')}_{item.get('reveal_mode', 'direct')}"
        grouped.setdefault(key, []).append(item)
    return {name: _latency_summary(items) for name, items in sorted(grouped.items())}


def _latency_summary_by_asset(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return apply-latency summaries for each measured asset/mode pair."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in results:
        key = (str(item.get("asset_id", "asset")), str(item.get("reveal_mode", "direct")))
        grouped.setdefault(key, []).append(item)
    summaries: list[dict[str, Any]] = []
    for (asset_id, reveal_mode), items in sorted(grouped.items()):
        summary = _latency_summary(items)
        summary.update(
            {
                "asset_id": asset_id,
                "reveal_mode": reveal_mode,
                "latency_class": str(items[0].get("latency_class", "cold")),
                "warm_standby": bool(items[0].get("warm_standby")),
                "route_state_ready_count": sum(1 for item in items if item.get("route_state_ready") is True),
            }
        )
        summaries.append(summary)
    return sorted(
        summaries,
        key=lambda item: (
            item["latency_class"] == "cold",
            item["asset_id"],
            item["reveal_mode"] != "direct",
        ),
    )


def _latency_distribution(prefix: str, values: list[float]) -> dict[str, float]:
    """Return a small percentile summary for one latency series."""
    return {
        f"{prefix}_min_ms": values[0],
        f"{prefix}_p50_ms": _percentile(values, 50),
        f"{prefix}_p90_ms": _percentile(values, 90),
        f"{prefix}_p95_ms": _percentile(values, 95),
        f"{prefix}_max_ms": values[-1],
    }


def _percentile(values: list[float], percentile: int) -> float:
    """Return a linearly interpolated percentile for a sorted value list."""
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    rank = (percentile / 100) * (len(values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return values[int(rank)]
    fraction = rank - lower
    return round(values[lower] + (values[upper] - values[lower]) * fraction, 3)


if __name__ == "__main__":
    raise SystemExit(main())
