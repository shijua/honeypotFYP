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

from libs.common.json_utils import read_json_value
from scripts.evaluation.charts import write_runtime_latency_chart


DEFAULT_ASSET_GATEWAY_PORTS = "18080,19418,13306,16379,18081,12121,12222,12323,2525,18082,18443,18085"


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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    catalog = read_json_value(Path(args.catalog), [])
    asset_ids = _selected_asset_ids(catalog, explicit=args.assets)
    if args.dry_run:
        print(json.dumps({"schema_version": "v1", "attacker_key": args.attacker_key, "assets": asset_ids}, indent=2, sort_keys=True))
        return 0

    binding, binding_latency = _resolve_binding(args.project_name, args.attacker_key)
    results = []
    for asset_id in asset_ids:
        results.append(
            _measure_asset(
                project_name=args.project_name,
                binding_id=binding["binding_id"],
                attacker_key=args.attacker_key,
                asset_id=asset_id,
                state_dir=Path(args.state_dir),
                route_timeout=args.route_timeout,
            )
        )

    report = {
        "schema_version": "v1",
        "attacker_key": args.attacker_key,
        "binding_id": binding["binding_id"],
        "binding_resolve_ms": binding_latency,
        "asset_count": len(results),
        "assets": results,
        "summary": _latency_summary(results),
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{text}\n", encoding="utf-8")
        write_runtime_latency_chart(report, args.output.with_suffix(".svg"))
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


def _measure_asset(
    *,
    project_name: str,
    binding_id: str,
    attacker_key: str,
    asset_id: str,
    state_dir: Path,
    route_timeout: float,
) -> dict[str, Any]:
    """Measure one asset reveal from controller action to gateway visibility.

    Returns:
        `orchestrator_apply_ms`: API time for `/v1/orchestration/apply`.
        `route_visible_ms`: extra polling time until `asset_gateway_routes.json`
        contains the attacker/asset route consumed by asset-gateway.
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
    # Then time data-plane visibility separately. A route can appear after the API returns.
    route_ms = _wait_for_route(state_dir / "asset_gateway_routes.json", attacker_key=attacker_key, asset_id=asset_id, timeout=route_timeout)
    runtime_event = next((item for item in response.get("runtime_events", []) if item.get("asset_id") == asset_id), {})
    return {
        "asset_id": asset_id,
        "ok": runtime_event.get("status") == "running" and route_ms is not None,
        "orchestrator_apply_ms": apply_ms,
        "route_visible_ms": route_ms,
        "runtime_status": runtime_event.get("status", "missing"),
        "runtime_backend": runtime_event.get("settings", {}).get("runtime_backend"),
        "route_updates": response.get("route_updates", []),
    }


def _wait_for_route(path: Path, *, attacker_key: str, asset_id: str, timeout: float) -> float | None:
    """Poll the route table; return elapsed ms when the expected route appears.

    Example:
        (attacker_key="146.169.44.23", asset_id="finance-share") -> 203.8
    """
    started = time.perf_counter()
    while time.perf_counter() - started <= timeout:
        routes = read_json_value(path, {"routes": []}).get("routes", [])
        if any(item.get("attacker_key") == attacker_key and item.get("asset_id") == asset_id for item in routes if isinstance(item, dict)):
            return _elapsed_ms(started)
        time.sleep(0.1)
    return None


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
    """Return ok/failed counts plus min/p50/max apply latency.

    Example:
        [{"ok": True, "orchestrator_apply_ms": 10.0}] -> {"ok_assets": 1, ...}
    """
    values = sorted(float(item["orchestrator_apply_ms"]) for item in results if isinstance(item.get("orchestrator_apply_ms"), (int, float)))
    if not values:
        return {"ok_assets": 0, "failed_assets": len(results)}
    return {
        "ok_assets": sum(1 for item in results if item["ok"]),
        "failed_assets": sum(1 for item in results if not item["ok"]),
        "apply_min_ms": values[0],
        "apply_p50_ms": values[len(values) // 2],
        "apply_max_ms": values[-1],
    }


if __name__ == "__main__":
    raise SystemExit(main())
