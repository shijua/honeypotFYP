#!/usr/bin/env python3
"""Forward Cowrie JSON log records into the local Cowrie adapter API.

Cowrie writes one JSON object per line to `var/log/cowrie/cowrie.json`. This
small bridge tails that file and POSTs each event to `services.cowrie.app`, so
real SSH honeypot activity flows into the same binding/profiler pipeline as the
rest of the MVP.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from scripts.forwarder_common import follow_file, forward_events, post_json_event
from scripts.forwarder_common import refresh_log_handle as _refresh_log_handle


def iter_json_events(lines: Iterable[str]) -> Iterator[dict[str, object]]:
    """Yield valid Cowrie JSON objects from newline-delimited log lines."""
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
    protocol: str = "ssh",
) -> dict[str, object]:
    """Wrap one Cowrie event in the adapter request schema."""
    return {"event": event, "protocol": protocol}


def normalize_event(event: dict[str, object]) -> dict[str, object] | None:
    """Return an adapter-safe event, or None for noisy Cowrie records.

    Cowrie occasionally emits structured fields where the adapter expects a
    scalar string. It also records empty shell submissions; those are useful for
    raw terminal replay, but they add noise to the MVP behavior profile.
    """
    eventid = event.get("eventid")
    if eventid == "cowrie.command.input":
        command = event.get("input")
        if not isinstance(command, str) or not command.strip():
            return None

    normalized = dict(event)
    message = normalized.get("message")
    if message is not None and not isinstance(message, str):
        normalized["message"] = json.dumps(message, sort_keys=True)
    return normalized


post_event = post_json_event


def forward_lines(
    lines: Iterable[str],
    adapter_url: str,
    protocol: str,
    timeout_seconds: float,
) -> int:
    """Forward a finite batch of Cowrie JSON lines and return success count."""
    def _payloads() -> Iterator[dict[str, object]]:
        for event in iter_json_events(lines):
            normalized = normalize_event(event)
            if normalized is None:
                print(f"Skipped noisy {event.get('eventid', '<unknown>')}", flush=True)
                continue
            yield build_adapter_payload(normalized, protocol=protocol)

    return forward_events(
        _payloads(),
        target_url=adapter_url,
        timeout_seconds=timeout_seconds,
        post_event=post_event,
        success_message=lambda payload: (
            f"Forwarded {_payload_event(payload).get('eventid', '<unknown>')}"
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
) -> int:
    """Tail a Cowrie JSON log file and forward new events to the adapter."""
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
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forward Cowrie cowrie.json lines to the MVP Cowrie adapter.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("deploy/cowrie/var/log/cowrie/cowrie.json"),
        help="Path to Cowrie's newline-delimited JSON log file.",
    )
    parser.add_argument(
        "--adapter-url",
        default="http://127.0.0.1:8081/v1/cowrie/events",
        help="Cowrie adapter endpoint.",
    )
    parser.add_argument(
        "--protocol",
        default="ssh",
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
    )
    if args.once:
        print(f"Forwarded {forwarded} Cowrie event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
