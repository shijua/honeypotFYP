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
import time
from pathlib import Path
from typing import Iterable, Iterator
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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


def post_event(
    payload: dict[str, object],
    adapter_url: str,
    timeout_seconds: float,
) -> tuple[int, str]:
    """POST one wrapped Cowrie event to the adapter API."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        adapter_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.status, response.read().decode("utf-8")


def forward_lines(
    lines: Iterable[str],
    adapter_url: str,
    protocol: str,
    timeout_seconds: float,
) -> int:
    """Forward a finite batch of Cowrie JSON lines and return success count."""
    forwarded = 0
    for event in iter_json_events(lines):
        normalized = normalize_event(event)
        if normalized is None:
            print(f"Skipped noisy {event.get('eventid', '<unknown>')}", flush=True)
            continue

        payload = build_adapter_payload(normalized, protocol=protocol)
        try:
            status_code, _ = post_event(payload, adapter_url, timeout_seconds)
        except HTTPError as exc:
            print(f"Adapter rejected event with HTTP {exc.code}", file=sys.stderr)
            continue
        except URLError as exc:
            print(f"Could not reach adapter: {exc}", file=sys.stderr)
            continue
        if 200 <= status_code < 300:
            forwarded += 1
            print(f"Forwarded {normalized.get('eventid', '<unknown>')}", flush=True)
        else:
            print(f"Adapter returned unexpected HTTP {status_code}", file=sys.stderr)
    return forwarded


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
    if not log_file.exists():
        # Create the path eagerly so the runner can start before Cowrie has
        # emitted its first event. In --once mode this simply forwards 0 events.
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.touch()
        # Local Docker Cowrie runs as a container user; keep a pre-created file
        # writable by that user if the forwarder starts first.
        log_file.chmod(0o666)

    forwarded = 0
    with log_file.open("r", encoding="utf-8") as handle:
        if not from_start:
            handle.seek(0, 2)

        while True:
            line = handle.readline()
            if line:
                forwarded += forward_lines(
                    [line],
                    adapter_url=adapter_url,
                    protocol=protocol,
                    timeout_seconds=timeout_seconds,
                )
                continue
            if once:
                return forwarded
            time.sleep(poll_seconds)


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
