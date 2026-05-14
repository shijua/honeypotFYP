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
from services.dashboard.summary import summarize_demo


LATER_ONLY_ASSETS = {
    "admin-jumpbox": "later/high-interaction path: separate Cowrie runtime log forwarding is not part of the fixed-port MVP smoke test",
    "log4shell-app": "later/high-interaction path: requires an isolated Vulhub checkout and compose-backed vulnerable runtime",
}
# Fixed-port OpenCanary assets record service names rather than catalog asset ids,
# so validation uses this bridge until service metadata is moved into catalog.
OPEN_CANARY_SERVICE_BY_ASSET = {
    "git-internal": "git",
    "ops-db": "mysql",
    "redis-cache": "redis",
    "ftp-archive": "ftp",
    "ssh-canary": "ssh",
    "legacy-telnet": "telnet",
    "mail-relay": "smtp",
}


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
        {"ok": true, "assets": [{"asset_id": "redis-cache", "telemetry": {"service": "redis"}}]}
    """
    catalog = read_json_value(catalog_path, [])
    assets = [
        item for item in catalog
        if isinstance(item, dict)
        and _asset_runtime_backend(item) in {"docker", "compose"}
        and (not asset_ids or item.get("asset_id") in asset_ids)
    ]
    runtime_records = _records(state_dir / "asset_runtime.json", "records")
    gateway_routes = _records(state_dir / "gateway_routes.json", "routes")
    asset_gateway_routes = _records(state_dir / "asset_gateway_routes.json", "routes")
    opencanary_observations = _records(state_dir / "opencanary_observations.json", "observations")
    internal_http_events = _jsonl_records(state_dir / "internal_http_events.jsonl")
    internal_protocol_events = _jsonl_records(state_dir / "internal_protocol_events.jsonl")
    dashboard_summary = summarize_demo(state_dir)

    asset_reports = [
        _asset_report(
            asset=asset,
            runtime_records=runtime_records,
            gateway_routes=gateway_routes,
            asset_gateway_routes=asset_gateway_routes,
            opencanary_observations=opencanary_observations,
            internal_http_events=internal_http_events,
            internal_protocol_events=internal_protocol_events,
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
    internal_http_events: list[dict[str, Any]],
    internal_protocol_events: list[dict[str, Any]],
    dashboard_summary: dict[str, Any],
) -> dict[str, Any]:
    """Summarize whether one catalog asset passed the MVP live-smoke checks.

    Example input:
        asset={"asset_id": "finance-share", "telemetry_source": "asset_runtime"}

    Example output:
        {"asset_id": "finance-share", "status": "ok", "asset_gateway_routed": true, "ok": true}
    """
    asset_id = str(asset.get("asset_id", ""))
    if asset_id in LATER_ONLY_ASSETS:
        return {
            "asset_id": asset_id,
            "runtime_backend": _asset_runtime_backend(asset),
            "status": "later",
            "limitation": LATER_ONLY_ASSETS[asset_id],
            "ok": True,
        }

    runtime_matches = [item for item in runtime_records if item.get("asset_id") == asset_id]
    gateway_exposed = any(asset_id in route.get("exposed_assets", []) for route in gateway_routes)
    gateway_failed = any(asset_id in route.get("failed_assets", []) for route in gateway_routes)
    asset_gateway_routed = any(route.get("asset_id") == asset_id for route in asset_gateway_routes)
    dashboard_running = _dashboard_has_asset(dashboard_summary, asset_id, "current_running_assets")
    dashboard_failed = _dashboard_has_asset(dashboard_summary, asset_id, "failed_assets")
    telemetry = _telemetry_report(
        asset=asset,
        opencanary_observations=opencanary_observations,
        internal_http_events=internal_http_events,
        internal_protocol_events=internal_protocol_events,
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
    internal_http_events: list[dict[str, Any]],
    internal_protocol_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Check the telemetry source expected for one asset.

    Example input:
        redis-cache with one OpenCanary observation whose service is "redis"

    Example output:
        {"kind": "opencanary", "service": "redis", "observed": true}
    """
    asset_id = str(asset.get("asset_id", ""))
    telemetry_source = str(asset.get("telemetry_source", ""))
    if telemetry_source == "asset_runtime":
        count = sum(1 for item in internal_http_events if item.get("asset_id") == asset_id)
        return {
            "kind": "internal_http",
            "observed": count > 0,
            "count": count,
            "expected_trigger": "HTTP request through the asset-gateway fixed port",
        }
    service = OPEN_CANARY_SERVICE_BY_ASSET.get(asset_id)
    if service:
        observation_count = sum(1 for item in opencanary_observations if item.get("service") == service)
        protocol_count = sum(
            1
            for item in internal_protocol_events
            if isinstance(item.get("logdata"), dict)
            and item["logdata"].get("ASSET_ID") == asset_id
        )
        return {
            "kind": "opencanary",
            "service": service,
            "observed": observation_count > 0 or protocol_count > 0,
            "observation_count": observation_count,
            "internal_protocol_event_count": protocol_count,
            "expected_trigger": f"{service} protocol probe through the asset-gateway fixed port",
        }
    return {
        "kind": telemetry_source or "unknown",
        "observed": False,
        "expected_trigger": "no fixed-port MVP telemetry trigger is configured for this asset",
    }


def _records(path: Path, key: str) -> list[dict[str, Any]]:
    """Read a JSON object list from a runtime file.

    Example:
        _records(Path("bindings.json"), "records") -> [{"binding_id": "..."}]
    """
    payload = read_json_value(path, {key: []})
    if not isinstance(payload, dict):
        return []
    records = payload.get(key, [])
    if not isinstance(records, list):
        return []
    return [item for item in records if isinstance(item, dict)]


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
