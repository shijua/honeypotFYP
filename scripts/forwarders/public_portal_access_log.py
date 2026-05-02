#!/usr/bin/env python3
"""Forward public portal nginx access logs into the entrypoint observer."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlsplit

from scripts.forwarders.common import follow_file, forward_events, post_json_event


_COMBINED_LOG_RE = re.compile(
    r'^(?P<remote_addr>\S+) \S+ \S+ \[[^\]]+\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) \S+ '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def iter_access_events(lines: Iterable[str]) -> Iterator[dict[str, object]]:
    """Yield normalized entrypoint events from nginx combined access logs."""
    for line_number, line in enumerate(lines, start=1):
        event = parse_access_line(line)
        if event is None:
            stripped = line.strip()
            if stripped:
                print(
                    f"Skipping unrecognized public portal log line {line_number}",
                    file=sys.stderr,
                )
            continue
        yield event


def parse_access_line(line: str) -> dict[str, object] | None:
    """Parse one nginx combined access log line into entrypoint event fields."""
    match = _COMBINED_LOG_RE.match(line.strip())
    if match is None:
        return None

    request_line = match.group("request")
    request_parts = request_line.split()
    if len(request_parts) < 2:
        return None
    method, target = request_parts[0], request_parts[1]
    if not method or not target or target == "-":
        return None

    parsed_target = urlsplit(target)
    path = parsed_target.path or "/"
    query_string = parsed_target.query
    user_agent = _empty_dash_to_none(match.group("user_agent"))
    referer = _empty_dash_to_none(match.group("referer"))
    headers: dict[str, str] = {}
    if user_agent:
        headers["user-agent"] = user_agent
    if referer:
        headers["referer"] = referer

    return {
        "attacker_key": match.group("remote_addr"),
        "method": method.upper(),
        "path": path,
        "query_string": query_string,
        "headers": headers,
        "body_preview": None,
        "body_truncated": False,
        "protocol": "http",
    }


post_event = post_json_event


def forward_lines(
    lines: Iterable[str],
    observer_url: str,
    timeout_seconds: float,
) -> int:
    """Forward a finite batch of nginx access lines and return success count."""
    return forward_events(
        iter_access_events(lines),
        target_url=observer_url,
        timeout_seconds=timeout_seconds,
        post_event=post_event,
        success_message=lambda event: f"Forwarded public-portal {event['method']} {event['path']}",
        rejected_label="public portal event",
    )


def follow_log_file(
    log_file: Path,
    observer_url: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
) -> int:
    """Tail an nginx access log and forward new public portal observations."""
    return follow_file(
        log_file,
        from_start=from_start,
        once=once,
        poll_seconds=poll_seconds,
        handle_line=lambda line: forward_lines(
            [line],
            observer_url=observer_url,
            timeout_seconds=timeout_seconds,
        ),
    )


def _empty_dash_to_none(value: str) -> str | None:
    return None if value in {"", "-"} else value


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Forward public portal nginx access logs to the entrypoint observer.",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path("deploy/public-portal/logs/access.log"),
        help="Path to the public portal nginx combined access log.",
    )
    parser.add_argument(
        "--observer-url",
        default="http://127.0.0.1:8010/v1/entrypoint/events",
        help="Entrypoint observer ingestion endpoint.",
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
        help="HTTP timeout when calling the entrypoint observer.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    forwarded = follow_log_file(
        log_file=args.log_file,
        observer_url=args.observer_url,
        from_start=args.from_start,
        once=args.once,
        poll_seconds=args.poll_seconds,
        timeout_seconds=args.timeout_seconds,
    )
    if args.once:
        print(f"Forwarded {forwarded} public portal event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
