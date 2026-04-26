#!/usr/bin/env python3
"""Forward OpenCanary JSON log records into the local OpenCanary adapter API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import IO, Iterable, Iterator, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


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


def post_event(
    payload: dict[str, object],
    adapter_url: str,
    timeout_seconds: float,
) -> tuple[int, str]:
    """POST one wrapped OpenCanary event to the adapter API."""
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
    """Forward a finite batch of OpenCanary JSON lines and return success count."""
    forwarded = 0
    for event in iter_json_events(lines):
        normalized = normalize_event(event)
        if normalized is None:
            print("Skipped OpenCanary event without src_host", flush=True)
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
            service = _event_service(normalized)
            print(f"Forwarded OpenCanary {service}", flush=True)
        else:
            print(f"Adapter returned unexpected HTTP {status_code}", file=sys.stderr)
    return forwarded


class _OpenLog(NamedTuple):
    handle: IO[str]
    identity: tuple[int, int]
    position: int


def follow_log_file(
    log_file: Path,
    adapter_url: str,
    protocol: str,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    timeout_seconds: float,
) -> int:
    """Tail an OpenCanary JSON log file and forward new events to the adapter."""
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
                    adapter_url=adapter_url,
                    protocol=protocol,
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
    """Open or reopen the log file when OpenCanary rotates or truncates it."""
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


def _event_service(event: dict[str, object]) -> str:
    logdata = event.get("logdata")
    if isinstance(logdata, dict):
        for key, value in logdata.items():
            if key.lower() == "service" and isinstance(value, str) and value:
                return value.lower()
    port = event.get("dst_port")
    return str(port) if port is not None else "event"


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
        print(f"Forwarded {forwarded} OpenCanary event(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

