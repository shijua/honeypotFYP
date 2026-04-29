#!/usr/bin/env python3
"""Forward public portal nginx access logs into the entrypoint observer."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import IO, Iterable, Iterator, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


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


def post_event(
    payload: dict[str, object],
    observer_url: str,
    timeout_seconds: float,
) -> tuple[int, str]:
    """POST one normalized public portal event to the entrypoint observer."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        observer_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.status, response.read().decode("utf-8")


def forward_lines(
    lines: Iterable[str],
    observer_url: str,
    timeout_seconds: float,
) -> int:
    """Forward a finite batch of nginx access lines and return success count."""
    forwarded = 0
    for event in iter_access_events(lines):
        try:
            status_code, _ = post_event(event, observer_url, timeout_seconds)
        except HTTPError as exc:
            print(f"Observer rejected public portal event with HTTP {exc.code}", file=sys.stderr)
            continue
        except URLError as exc:
            print(f"Could not reach entrypoint observer: {exc}", file=sys.stderr)
            continue
        if 200 <= status_code < 300:
            forwarded += 1
            print(
                f"Forwarded public-portal {event['method']} {event['path']}",
                flush=True,
            )
        else:
            print(f"Observer returned unexpected HTTP {status_code}", file=sys.stderr)
    return forwarded


class _OpenLog(NamedTuple):
    handle: IO[str]
    identity: tuple[int, int]
    position: int


def follow_log_file(
    log_file: Path,
    observer_url: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
) -> int:
    """Tail an nginx access log and forward new public portal observations."""
    forwarded = 0
    current_log: _OpenLog | None = None
    initial_open = True
    try:
        while True:
            current_log = _refresh_log_handle(
                log_file,
                current_log,
                from_start=from_start,
                initial_open=initial_open,
            )
            initial_open = False

            line = current_log.handle.readline()
            if line:
                forwarded += forward_lines(
                    [line],
                    observer_url=observer_url,
                    timeout_seconds=timeout_seconds,
                )
                current_log = current_log._replace(position=current_log.handle.tell())
                continue
            if once:
                return forwarded
            time.sleep(poll_seconds)
    finally:
        if current_log is not None:
            current_log.handle.close()


def _refresh_log_handle(
    log_file: Path,
    current_log: _OpenLog | None,
    *,
    from_start: bool,
    initial_open: bool,
) -> _OpenLog:
    """Open or reopen the log file when nginx rotates or truncates it."""
    _ensure_log_file(log_file)
    stat_result = log_file.stat()
    identity = (stat_result.st_dev, stat_result.st_ino)
    should_reopen = (
        current_log is None
        or current_log.identity != identity
        or stat_result.st_size < current_log.position
    )
    if not should_reopen:
        return current_log

    if current_log is not None:
        current_log.handle.close()

    handle = log_file.open("r", encoding="utf-8")
    if initial_open and not from_start:
        handle.seek(0, os.SEEK_END)
    else:
        handle.seek(0)
    return _OpenLog(handle=handle, identity=identity, position=handle.tell())


def _ensure_log_file(log_file: Path) -> None:
    if log_file.exists():
        return
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.touch()
    log_file.chmod(0o666)


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
