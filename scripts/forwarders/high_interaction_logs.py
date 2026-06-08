#!/usr/bin/env python3
"""Forward high-interaction backend logs into the high-interaction adapter.

The supported raw input is intentionally broad: a JSON line is passed through
as structured logdata, while a plain text line becomes `logdata.message`. The
adapter receives one normalized event with an explicit `source`, `service`,
`event_type`, `asset_id`, and attacker key. Glutton generic capture currently
uses `source=honeytrap` as the normalized compatibility label.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from libs.common.json_utils import first_string, first_value
from scripts.forwarders.common import follow_file, forward_events, load_asset_gateway_routes
from scripts.forwarders.common import payload_event, post_json_event, route_attacker_key
from scripts.forwarders.common import safe_int


LOGDATA_OMIT_KEYS = {
    "source",
    "asset_id",
    "service",
    "protocol",
    "event_type",
    "eventid",
    "attacker_key",
    "src_ip",
    "src_host",
    "dst_ip",
    "dst_host",
    "dest_ip",
    "dest_port",
    "dst_port",
    "local_host",
    "local_ip",
    "local_port",
    "timestamp",
    "ts",
}


def iter_log_events(lines: Iterable[str]) -> Iterator[dict[str, object]]:
    """Yield a dict for each JSON or plain-text high-interaction log line.

    Example:
        '{"src_ip":"198.51.100.10","event_type":"modbus.read"}' -> parsed dict
        'connection from 198.51.100.10' -> {"message": "..."}
    """
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            yield {"message": stripped}
            continue
        if isinstance(item, dict):
            yield item
        else:
            print(f"Skipping non-object JSON on line {line_number}", file=sys.stderr)


def build_adapter_payload(
    event: dict[str, object],
    *,
    source: str,
    asset_id: str,
    service: str,
    event_type: str,
    protocol: str,
    asset_routes: list[dict[str, object]],
) -> dict[str, object] | None:
    """Normalize one raw line into the high-interaction adapter schema.

    Example output:
        {"event": {"source": "dionaea", "asset_id": "dionaea-capture", "attacker_key": "198.51.100.10", ...}}
    """
    normalized = dict(event)
    normalized_source = _string_field(normalized, "source", default=source)
    normalized_asset_id = _string_field(normalized, "asset_id", default=asset_id)
    normalized_service = _string_field(
        normalized,
        "service",
        "protocol",
        default=service,
    )
    normalized_event_type = _string_field(
        normalized,
        "event_type",
        "eventid",
        default=event_type,
    )
    dst_port = safe_int(first_value(normalized, "dst_port", "dest_port", "local_port", "port"))
    dst_host = first_string(normalized, "dst_host", "dest_ip", "local_host", "local_ip")
    attacker_key = _attacker_key(normalized, normalized_asset_id, dst_host, dst_port, asset_routes)
    if not attacker_key:
        print("Skipped high-interaction event without attacker source", flush=True)
        return None

    adapter_event: dict[str, object] = {
        "source": normalized_source,
        "asset_id": normalized_asset_id,
        "attacker_key": attacker_key,
        "service": normalized_service,
        "event_type": normalized_event_type,
        "src_host": first_string(normalized, "src_host", "src_ip", "remote_host", "remote_ip") or attacker_key,
        "src_port": safe_int(first_value(normalized, "src_port", "source_port", "remote_port")),
        "dst_host": dst_host,
        "dst_port": dst_port,
        "logdata": _logdata(normalized),
    }
    ts = first_string(normalized, "ts", "timestamp", "time")
    if ts:
        adapter_event["ts"] = ts
    return {"event": adapter_event, "protocol": protocol}


post_event = post_json_event


def forward_lines(
    lines: Iterable[str],
    *,
    adapter_url: str,
    source: str,
    asset_id: str,
    service: str,
    event_type: str,
    protocol: str,
    timeout_seconds: float,
    asset_routes_file: Path | None = None,
) -> int:
    """Forward a finite batch of log lines and return the successful count."""
    asset_routes = load_asset_gateway_routes(asset_routes_file)

    def _payloads() -> Iterator[dict[str, object]]:
        for event in iter_log_events(lines):
            payload = build_adapter_payload(
                event,
                source=source,
                asset_id=asset_id,
                service=service,
                event_type=event_type,
                protocol=protocol,
                asset_routes=asset_routes,
            )
            if payload is not None:
                yield payload

    return forward_events(
        _payloads(),
        target_url=adapter_url,
        timeout_seconds=timeout_seconds,
        post_event=post_event,
        success_message=_success_message,
        rejected_label="event",
        endpoint_label="Adapter",
        unreachable_target="high-interaction adapter",
    )


def _string_field(
    event: dict[str, object],
    *keys: str,
    default: str,
) -> str:
    """Return the first non-empty event string or a required CLI default."""
    return first_string(event, *keys) or default


def _attacker_key(
    event: dict[str, object],
    asset_id: str,
    dst_host: str | None,
    dst_port: int | None,
    asset_routes: list[dict[str, object]],
) -> str | None:
    """Find attacker identity from raw event fields or the asset-gateway route."""
    attacker_key = first_string(
        event,
        "attacker_key",
        "src_ip",
        "src_host",
        "remote_host",
        "remote_ip",
        "source_ip",
    )
    if attacker_key:
        return attacker_key
    return route_attacker_key(
        asset_routes,
        asset_id=asset_id,
        backend_host=dst_host,
        backend_port=dst_port,
    )


def _logdata(event: dict[str, object]) -> dict[str, object]:
    """Return backend-specific fields after adapter envelope fields are removed."""
    return {
        key: value
        for key, value in event.items()
        if key not in LOGDATA_OMIT_KEYS
    }


def _success_message(payload: dict[str, object]) -> str:
    event = payload_event(payload)
    return (
        f"Forwarded high-interaction {event.get('source')} "
        f"{event.get('asset_id')}"
    )


def follow_log_file(
    *,
    log_file: Path,
    adapter_url: str,
    source: str,
    asset_id: str,
    service: str,
    event_type: str,
    protocol: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
    asset_routes_file: Path | None,
) -> int:
    """Tail one backend log file and forward normalized events."""
    return follow_file(
        log_file,
        from_start=from_start,
        once=once,
        poll_seconds=poll_seconds,
        handle_line=lambda line: forward_lines(
            [line],
            adapter_url=adapter_url,
            source=source,
            asset_id=asset_id,
            service=service,
            event_type=event_type,
            protocol=protocol,
            timeout_seconds=timeout_seconds,
            asset_routes_file=asset_routes_file,
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Forward high-interaction honeypot logs.")
    parser.add_argument("--log-file", type=Path, required=True)
    parser.add_argument("--adapter-url", default="http://127.0.0.1:8014/v1/high-interaction/events")
    parser.add_argument("--source", choices=["dionaea", "honeytrap"], required=True)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--service", default="unknown")
    parser.add_argument("--event-type", default="interaction")
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--asset-routes-file", type=Path, default=Path("data/runtime/asset_gateway_routes.json"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    forwarded = follow_log_file(
        log_file=args.log_file,
        adapter_url=args.adapter_url,
        source=args.source,
        asset_id=args.asset_id,
        service=args.service,
        event_type=args.event_type,
        protocol=args.protocol,
        from_start=args.from_start,
        once=args.once,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
        asset_routes_file=args.asset_routes_file,
    )
    if args.once:
        print(f"Forwarded {forwarded} high-interaction event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
