#!/usr/bin/env python3
"""Forward asset-gateway internal HTTP JSONL events to entrypoint observer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Iterator

from scripts.forwarder_common import follow_file, forward_events, post_json_event


def iter_json_events(lines: Iterable[str]) -> Iterator[dict[str, object]]:
    """Yield valid internal HTTP event objects from newline-delimited JSON."""
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as exc:
            print(
                f"Skipping invalid internal HTTP JSON on line {line_number}: {exc}",
                file=sys.stderr,
            )
            continue
        if not isinstance(event, dict):
            print(
                f"Skipping non-object internal HTTP JSON on line {line_number}",
                file=sys.stderr,
            )
            continue
        yield event


post_event = post_json_event


def forward_lines(
    lines: Iterable[str],
    observer_url: str,
    timeout_seconds: float,
) -> int:
    """Forward a finite batch of internal HTTP JSONL lines."""
    return forward_events(
        iter_json_events(lines),
        target_url=observer_url,
        timeout_seconds=timeout_seconds,
        post_event=post_event,
        success_message=lambda event: (
            f"Forwarded internal-http {event.get('method', 'HTTP')} {event.get('path', '/')}"
        ),
        rejected_label="internal HTTP event",
    )


def follow_log_file(
    events_file: Path,
    observer_url: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
) -> int:
    """Tail asset-gateway JSONL events and forward them to the observer."""
    return follow_file(
        events_file,
        from_start=from_start,
        once=once,
        poll_seconds=poll_seconds,
        handle_line=lambda line: forward_lines(
            [line],
            observer_url=observer_url,
            timeout_seconds=timeout_seconds,
        ),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forward asset-gateway internal HTTP JSONL events.",
    )
    parser.add_argument(
        "--events-file",
        type=Path,
        default=Path("data/runtime/internal_http_events.jsonl"),
        help="Path to the asset-gateway internal HTTP JSONL event file.",
    )
    parser.add_argument(
        "--observer-url",
        default="http://127.0.0.1:8010/v1/entrypoint/events",
        help="Entrypoint observer ingestion endpoint.",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Forward existing JSONL events before tailing new lines.",
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
        help="Sleep interval while waiting for new JSONL lines.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=5.0,
        help="HTTP timeout when calling the entrypoint observer.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    forwarded = follow_log_file(
        events_file=args.events_file,
        observer_url=args.observer_url,
        from_start=args.from_start,
        once=args.once,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
    )
    if args.once:
        print(f"Forwarded {forwarded} internal HTTP event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
