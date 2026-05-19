#!/usr/bin/env python3
"""Validate that runtime-enabled assets left data in the adaptive pipeline.

Example:
    .venv/bin/python scripts/validation/asset_telemetry.py --require-observed

Output:
    {"ok": true, "assets": [{"asset_id": "internal-portal", ...}]}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from libs.common.json_utils import read_json_value
from libs.common.runtime_records import list_records
from services.dashboard.summary import summarize_demo


def main() -> int:
    """Parse CLI flags, print the validation report, and return a shell status.

    Example:
        --asset-id redis-cache --require-observed

    Output:
        0 when the selected required assets are observed, otherwise 1.
    """
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
    """Build one validation report from catalog and runtime state files.

    Example input:
        catalog_path=data/assets/catalog.json, state_dir=data/runtime, asset_ids={"redis-cache"}

    Example output:
        {"ok": true, "assets": [{"asset_id": "redis-cache", "telemetry": {"kind": "opencanary"}}]}
    """
    catalog = read_json_value(catalog_path, [])
    assets = [
        item for item in catalog
        if isinstance(item, dict)
        and _asset_runtime_backend(item) in {"docker", "compose"}
        and (not asset_ids or item.get("asset_id") in asset_ids)
    ]
    runtime_records = list_records(state_dir / "asset_runtime.json", "records")
    gateway_routes = list_records(state_dir / "gateway_routes.json", "routes")
    asset_gateway_routes = list_records(state_dir / "asset_gateway_routes.json", "routes")
    opencanary_observations = list_records(state_dir / "opencanary_observations.json", "observations")
    cowrie_observations = list_records(state_dir / "cowrie_observations.json", "observations")
    high_interaction_observations = list_records(state_dir / "high_interaction_observations.json", "observations")
    internal_http_events = _jsonl_records(state_dir / "internal_http_events.jsonl")
    internal_protocol_events = _jsonl_records(state_dir / "internal_protocol_events.jsonl")
    high_interaction_events = _jsonl_records(state_dir / "high_interaction_events.jsonl")
    dashboard_summary = summarize_demo(state_dir)

    asset_reports = [
        _asset_report(
            asset=asset,
            runtime_records=runtime_records,
            gateway_routes=gateway_routes,
            asset_gateway_routes=asset_gateway_routes,
            opencanary_observations=opencanary_observations,
            cowrie_observations=cowrie_observations,
            high_interaction_observations=high_interaction_observations,
            internal_http_events=internal_http_events,
            internal_protocol_events=internal_protocol_events,
            high_interaction_events=high_interaction_events,
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
    asset_gateway_routes: list[dict[str, Any]],
    opencanary_observations: list[dict[str, Any]],
    cowrie_observations: list[dict[str, Any]],
    high_interaction_observations: list[dict[str, Any]],
    internal_http_events: list[dict[str, Any]],
    internal_protocol_events: list[dict[str, Any]],
    high_interaction_events: list[dict[str, Any]],
    dashboard_summary: dict[str, Any],
) -> dict[str, Any]:
    """Summarize whether one catalog asset passed the MVP live-smoke checks.

    Example input:
        asset={"asset_id": "finance-share", "telemetry_source": "asset_runtime"}

    Example output:
        {"asset_id": "finance-share", "status": "ok", "asset_gateway_routed": true, "ok": true}
    """
    asset_id = str(asset.get("asset_id", ""))
    runtime_matches = [item for item in runtime_records if item.get("asset_id") == asset_id]
    gateway_exposed = any(asset_id in route.get("exposed_assets", []) for route in gateway_routes)
    gateway_failed = any(asset_id in route.get("failed_assets", []) for route in gateway_routes)
    asset_gateway_routed = any(route.get("asset_id") == asset_id for route in asset_gateway_routes)
    dashboard_running = _dashboard_has_asset(dashboard_summary, asset_id, "current_running_assets")
    dashboard_failed = _dashboard_has_asset(dashboard_summary, asset_id, "failed_assets")
    telemetry = _telemetry_report(
        asset=asset,
        opencanary_observations=opencanary_observations,
        cowrie_observations=cowrie_observations,
        high_interaction_observations=high_interaction_observations,
        internal_http_events=internal_http_events,
        internal_protocol_events=internal_protocol_events,
        high_interaction_events=high_interaction_events,
    )
    observed = (
        bool(runtime_matches)
        and asset_gateway_routed
        and dashboard_running
        and telemetry["observed"]
    )
    return {
        "asset_id": asset_id,
        "runtime_backend": _asset_runtime_backend(asset),
        "telemetry_source": str(asset.get("telemetry_source", "")),
        "runtime_record_count": len(runtime_matches),
        "gateway_exposed": gateway_exposed,
        "gateway_failed": gateway_failed,
        "asset_gateway_routed": asset_gateway_routed,
        "dashboard_running": dashboard_running,
        "dashboard_failed": dashboard_failed,
        "telemetry_expectations": _telemetry_expectations(asset),
        "telemetry": telemetry,
        "status": "ok" if observed else "missing",
        "ok": observed,
    }


def _dashboard_has_asset(summary: dict[str, Any], asset_id: str, bucket: str) -> bool:
    """Return whether the dashboard currently lists an asset in a named bucket.

    Example:
        _dashboard_has_asset(summary, "redis-cache", "current_running_assets") -> True
    """
    for attacker in summary.get("attackers", []):
        if not isinstance(attacker, dict):
            continue
        for item in attacker.get(bucket, []):
            if isinstance(item, dict) and item.get("asset_id") == asset_id:
                return True
    return False


def _asset_runtime_backend(asset: dict[str, Any]) -> str:
    """Extract the runtime backend from a catalog asset.

    Example:
        {"default_settings": {"runtime": {"backend": "docker"}}} -> "docker"
    """
    default_settings = asset.get("default_settings", {})
    if not isinstance(default_settings, dict):
        return "mock"
    runtime = default_settings.get("runtime", {})
    if not isinstance(runtime, dict):
        return "mock"
    return str(runtime.get("backend", "mock"))


def _telemetry_expectations(asset: dict[str, Any]) -> list[str]:
    """Return optional catalog telemetry expectation labels.

    Example:
        {"default_settings": {"telemetry_expectations": ["gateway_route"]}} -> ["gateway_route"]
    """
    default_settings = asset.get("default_settings", {})
    if not isinstance(default_settings, dict):
        return []
    expectations = default_settings.get("telemetry_expectations", [])
    if not isinstance(expectations, list):
        return []
    return [str(item) for item in expectations]


def _telemetry_report(
    *,
    asset: dict[str, Any],
    opencanary_observations: list[dict[str, Any]],
    cowrie_observations: list[dict[str, Any]],
    high_interaction_observations: list[dict[str, Any]],
    internal_http_events: list[dict[str, Any]],
    internal_protocol_events: list[dict[str, Any]],
    high_interaction_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Check the telemetry source expected for one asset.

    Example input:
        redis-cache with one OpenCanary observation whose service is "redis"

    Example output:
        {"kind": "opencanary", "service": "redis", "observed": true}
    """
    asset_id = str(asset.get("asset_id", ""))
    telemetry_source = str(asset.get("telemetry_source", ""))
    validation = _telemetry_validation(asset)
    validation_kind = str(validation.get("kind") or telemetry_source)
    if validation_kind == "asset_runtime":
        count = _count_asset_records(internal_http_events, asset_id)
        return {
            "kind": "internal_http",
            "observed": count > 0,
            "count": count,
            "expected_trigger": _expected_trigger(validation),
        }
    if validation_kind == "cowrie":
        count = _count_asset_records(cowrie_observations, asset_id)
        return {
            "kind": "cowrie",
            "observed": count > 0,
            "count": count,
            "expected_trigger": _expected_trigger(validation),
        }
    if validation_kind == "high_interaction":
        source = str(validation.get("source") or "high_interaction")
        observation_count = _count_asset_records(high_interaction_observations, asset_id)
        raw_count = _count_asset_records(high_interaction_events, asset_id)
        http_count = _count_asset_records(internal_http_events, asset_id)
        return {
            "kind": "high_interaction",
            "source": source,
            "observed": observation_count > 0 or raw_count > 0 or http_count > 0,
            "observation_count": observation_count,
            "raw_event_count": raw_count,
            "internal_http_event_count": http_count,
            "expected_trigger": _expected_trigger(validation),
        }
    if validation_kind in {"opencanary", "mailoney"}:
        service = str(validation.get("service") or "")
        observation_count = sum(1 for item in opencanary_observations if item.get("service") == service)
        protocol_count = sum(
            1
            for item in internal_protocol_events
            if isinstance(item.get("logdata"), dict)
            and item["logdata"].get("ASSET_ID") == asset_id
        )
        return {
            "kind": validation_kind,
            "service": service,
            "observed": observation_count > 0 or protocol_count > 0,
            "observation_count": observation_count,
            "internal_protocol_event_count": protocol_count,
            "expected_trigger": _expected_trigger(validation),
        }
    return {
        "kind": telemetry_source or "unknown",
        "observed": False,
        "expected_trigger": "no fixed-port MVP telemetry trigger is configured for this asset",
    }


def _telemetry_validation(asset: dict[str, Any]) -> dict[str, Any]:
    """Return catalog-declared validation metadata for one asset.

    Example:
        {"default_settings": {"telemetry_validation": {"kind": "opencanary", "service": "redis"}}}
        -> {"kind": "opencanary", "service": "redis"}
    """
    default_settings = asset.get("default_settings", {})
    if not isinstance(default_settings, dict):
        return {}
    validation = default_settings.get("telemetry_validation", {})
    return validation if isinstance(validation, dict) else {}


def _expected_trigger(validation: dict[str, Any]) -> str:
    """Return catalog text explaining how to trigger telemetry for an asset."""
    value = validation.get("expected_trigger")
    return str(value) if isinstance(value, str) and value else "catalog telemetry trigger"


def _count_asset_records(records: list[dict[str, Any]], asset_id: str) -> int:
    """Count records that explicitly belong to the requested asset.

    Example:
        _count_asset_records([{"asset_id": "admin-jumpbox"}], "admin-jumpbox") -> 1
    """
    return sum(1 for item in records if item.get("asset_id") == asset_id)


def _jsonl_records(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited JSON events, skipping blank or malformed lines.

    Example:
        internal_http_events.jsonl line {"asset_id":"internal-portal"} -> [{"asset_id":"internal-portal"}]
    """
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


if __name__ == "__main__":
    raise SystemExit(main())
