#!/usr/bin/env python3
"""Validate that runtime-enabled assets left data in the adaptive pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from services.dashboard.summary import summarize_demo


def main() -> int:
    parser = argparse.ArgumentParser(description="Check asset runtime/gateway/dashboard data.")
    parser.add_argument("--catalog", default="data/assets/catalog.json")
    parser.add_argument("--state-dir", default="data/runtime")
    parser.add_argument("--asset-id", action="append", default=[])
    parser.add_argument("--require-observed", action="store_true")
    args = parser.parse_args()

    report = build_report(
        catalog_path=Path(args.catalog),
        state_dir=Path(args.state_dir),
        asset_ids=set(args.asset_id),
    )
    print(json.dumps(report, indent=2, sort_keys=True))

    if args.require_observed and any(not item["ok"] for item in report["assets"]):
        return 1
    return 0


def build_report(
    *,
    catalog_path: Path,
    state_dir: Path,
    asset_ids: set[str],
) -> dict[str, Any]:
    catalog = _read_json(catalog_path, [])
    assets = [
        item for item in catalog
        if isinstance(item, dict)
        and _asset_runtime_backend(item) in {"docker", "compose"}
        and (not asset_ids or item.get("asset_id") in asset_ids)
    ]
    runtime_records = _records(state_dir / "asset_runtime.json", "records")
    gateway_routes = _records(state_dir / "gateway_routes.json", "routes")
    dashboard_summary = summarize_demo(state_dir)

    asset_reports = [
        _asset_report(
            asset=asset,
            runtime_records=runtime_records,
            gateway_routes=gateway_routes,
            dashboard_summary=dashboard_summary,
        )
        for asset in assets
    ]
    return {
        "schema_version": "v1",
        "catalog": str(catalog_path),
        "state_dir": str(state_dir),
        "assets": asset_reports,
        "ok": all(item["ok"] for item in asset_reports),
    }


def _asset_report(
    *,
    asset: dict[str, Any],
    runtime_records: list[dict[str, Any]],
    gateway_routes: list[dict[str, Any]],
    dashboard_summary: dict[str, Any],
) -> dict[str, Any]:
    asset_id = str(asset.get("asset_id", ""))
    runtime_matches = [item for item in runtime_records if item.get("asset_id") == asset_id]
    gateway_exposed = any(asset_id in route.get("exposed_assets", []) for route in gateway_routes)
    gateway_failed = any(asset_id in route.get("failed_assets", []) for route in gateway_routes)
    dashboard_running = _dashboard_has_asset(dashboard_summary, asset_id, "current_running_assets")
    dashboard_failed = _dashboard_has_asset(dashboard_summary, asset_id, "failed_assets")
    observed = bool(runtime_matches) and (gateway_exposed or gateway_failed) and (dashboard_running or dashboard_failed)
    return {
        "asset_id": asset_id,
        "runtime_backend": _asset_runtime_backend(asset),
        "runtime_record_count": len(runtime_matches),
        "gateway_exposed": gateway_exposed,
        "gateway_failed": gateway_failed,
        "dashboard_running": dashboard_running,
        "dashboard_failed": dashboard_failed,
        "telemetry_expectations": _telemetry_expectations(asset),
        "ok": observed,
    }


def _dashboard_has_asset(summary: dict[str, Any], asset_id: str, bucket: str) -> bool:
    for attacker in summary.get("attackers", []):
        if not isinstance(attacker, dict):
            continue
        for item in attacker.get(bucket, []):
            if isinstance(item, dict) and item.get("asset_id") == asset_id:
                return True
    return False


def _asset_runtime_backend(asset: dict[str, Any]) -> str:
    default_settings = asset.get("default_settings", {})
    if not isinstance(default_settings, dict):
        return "mock"
    runtime = default_settings.get("runtime", {})
    if not isinstance(runtime, dict):
        return "mock"
    return str(runtime.get("backend", "mock"))


def _telemetry_expectations(asset: dict[str, Any]) -> list[str]:
    default_settings = asset.get("default_settings", {})
    if not isinstance(default_settings, dict):
        return []
    expectations = default_settings.get("telemetry_expectations", [])
    if not isinstance(expectations, list):
        return []
    return [str(item) for item in expectations]


def _records(path: Path, key: str) -> list[dict[str, Any]]:
    payload = _read_json(path, {key: []})
    if not isinstance(payload, dict):
        return []
    records = payload.get(key, [])
    if not isinstance(records, list):
        return []
    return [item for item in records if isinstance(item, dict)]


def _read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


if __name__ == "__main__":
    raise SystemExit(main())
