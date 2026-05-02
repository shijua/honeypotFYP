#!/usr/bin/env python3
"""Forward OpenCanary JSON log records into the local OpenCanary adapter API."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from scripts.forwarders.common import follow_file, forward_events, post_json_event
from scripts.forwarders.common import refresh_log_handle as _refresh_log_handle


def iter_json_events(lines: Iterable[str]) -> Iterator[dict[str, object]]:
    """Yield valid OpenCanary JSON objects from newline-delimited log lines."""
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            print(
                f"Skipping invalid JSON on line {line_number}: {exc}",
                file=sys.stderr,
            )
            continue
        if not isinstance(event, dict):
            print(
                f"Skipping non-object JSON on line {line_number}",
                file=sys.stderr,
            )
            continue
        yield event


def build_adapter_payload(
    event: dict[str, object],
    protocol: str = "tcp",
) -> dict[str, object]:
    """Wrap one OpenCanary event in the adapter request schema."""
    return {"event": event, "protocol": protocol}


def normalize_event(event: dict[str, object]) -> dict[str, object] | None:
    """Return an adapter-safe OpenCanary event, or None for unusable records."""
    src_host = event.get("src_host")
    if not isinstance(src_host, str) or not src_host.strip():
        return None

    normalized = dict(event)
    logdata = normalized.get("logdata")
    if logdata is None:
        normalized["logdata"] = {}
    elif not isinstance(logdata, dict):
        normalized["logdata"] = {"message": json.dumps(logdata, sort_keys=True)}
    return normalized


def load_asset_gateway_routes(route_file: Path | None) -> list[dict[str, object]]:
    """Load routes used to attribute proxied OpenCanary events to attackers."""
    if route_file is None:
        return []
    try:
        payload = json.loads(route_file.read_text(encoding="utf-8"))
    except Exception:
        return []
    routes = payload.get("routes", []) if isinstance(payload, dict) else []
    if not isinstance(routes, list):
        return []
    return [route for route in routes if isinstance(route, dict)]


def attribute_asset_gateway_source(
    event: dict[str, object],
    routes: list[dict[str, object]],
) -> dict[str, object]:
    """Replace the proxy source IP with the route's original attacker IP."""
    dst_host = event.get("dst_host")
    dst_port = event.get("dst_port")
    if not isinstance(dst_host, str) or not isinstance(dst_port, int):
        return event

    matches = [
        route
        for route in routes
        if route.get("backend_ip") == dst_host
        and _safe_int(route.get("backend_port")) == dst_port
    ]
    if len(matches) != 1:
        return event

    attacker_key = str(matches[0].get("attacker_key", "")).strip()
    if not attacker_key:
        return event

    attributed = dict(event)
    original_src_host = str(attributed.get("src_host", ""))
    attributed["src_host"] = attacker_key
    logdata = attributed.get("logdata")
    if not isinstance(logdata, dict):
        logdata = {}
    else:
        logdata = dict(logdata)
    if original_src_host:
        logdata["ASSET_GATEWAY_PROXY_SRC_HOST"] = original_src_host
    logdata["ASSET_GATEWAY_BACKEND_HOST"] = str(matches[0].get("backend_host", ""))
    logdata["ASSET_GATEWAY_PUBLIC_PORT"] = matches[0].get("public_port", "")
    attributed["logdata"] = logdata
    return attributed


post_event = post_json_event


def forward_lines(
    lines: Iterable[str],
    adapter_url: str,
    protocol: str,
    timeout_seconds: float,
    asset_routes_file: Path | None = None,
) -> int:
    """Forward a finite batch of OpenCanary JSON lines and return success count."""
    asset_routes = load_asset_gateway_routes(asset_routes_file)

    def _payloads() -> Iterator[dict[str, object]]:
        for event in iter_json_events(lines):
            normalized = normalize_event(event)
            if normalized is None:
                print("Ignored OpenCanary lifecycle event without src_host", flush=True)
                continue
            normalized = attribute_asset_gateway_source(normalized, asset_routes)
            yield build_adapter_payload(normalized, protocol=protocol)

    return forward_events(
        _payloads(),
        target_url=adapter_url,
        timeout_seconds=timeout_seconds,
        post_event=post_event,
        success_message=lambda payload: (
            f"Forwarded OpenCanary {_event_service(_payload_event(payload))}"
        ),
        rejected_label="event",
        endpoint_label="Adapter",
        unreachable_target="adapter",
    )


def _payload_event(payload: dict[str, object]) -> dict[str, object]:
    event = payload.get("event")
    if isinstance(event, dict):
        return event
    return {}


def follow_log_file(
    log_file: Path,
    adapter_url: str,
    protocol: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
    asset_routes_file: Path | None,
) -> int:
    """Tail an OpenCanary JSON log file and forward new events to the adapter."""
    return follow_file(
        log_file,
        from_start=from_start,
        once=once,
        poll_seconds=poll_seconds,
        handle_line=lambda line: forward_lines(
            [line],
            adapter_url=adapter_url,
            protocol=protocol,
            timeout_seconds=timeout_seconds,
            asset_routes_file=asset_routes_file,
        ),
    )


def _event_service(event: dict[str, object]) -> str:
    logdata = event.get("logdata")
    if isinstance(logdata, dict):
        for key, value in logdata.items():
            if key.lower() == "service" and isinstance(value, str) and value:
                return value.lower()
    port = event.get("dst_port")
    return str(port) if port is not None else "event"


def _safe_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forward OpenCanary JSON lines to the MVP OpenCanary adapter.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("deploy/opencanary/var/opencanary.log"),
        help="Path to OpenCanary's newline-delimited JSON log file.",
    )
    parser.add_argument(
        "--adapter-url",
        default="http://127.0.0.1:8012/v1/opencanary/events",
        help="OpenCanary adapter endpoint.",
    )
    parser.add_argument(
        "--protocol",
        default="tcp",
        help="Protocol value stored on binding records.",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Forward existing log lines before tailing new lines.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process the current file contents once and exit.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=1.0,
        help="Sleep interval while waiting for new log lines.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=5.0,
        help="HTTP timeout when calling the adapter.",
    )
    parser.add_argument(
        "--asset-routes-file",
        type=Path,
        default=Path("data/runtime/asset_gateway_routes.json"),
        help="Asset gateway route table used to restore original attacker IPs.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    forwarded = follow_log_file(
        log_file=args.log_file,
        adapter_url=args.adapter_url,
        protocol=args.protocol,
        from_start=args.from_start,
        once=args.once,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
        asset_routes_file=args.asset_routes_file,
    )
    if args.once:
        print(f"Forwarded {forwarded} OpenCanary event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
