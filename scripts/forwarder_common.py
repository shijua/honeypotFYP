#!/usr/bin/env python3
"""Shared file-tail and JSON POST helpers for lightweight forwarders."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Callable, IO, Iterable, NamedTuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OpenLog(NamedTuple):
    """Current open file handle plus enough state to detect rotation."""

    handle: IO[str]
    identity: tuple[int, int]
    position: int


def post_json_event(
    payload: dict[str, object],
    target_url: str,
    timeout_seconds: float,
) -> tuple[int, str]:
    """POST one JSON payload to a local adapter or observer endpoint."""
    body = json.dumps(payload).encode("utf-8")
    request = Request(
        target_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.status, response.read().decode("utf-8")


def forward_events(
    events: Iterable[dict[str, object]],
    *,
    target_url: str,
    timeout_seconds: float,
    post_event: Callable[[dict[str, object], str, float], tuple[int, str]],
    success_message: Callable[[dict[str, object]], str],
    rejected_label: str,
    endpoint_label: str = "Observer",
    unreachable_target: str = "entrypoint observer",
) -> int:
    """POST parsed events and print consistent forwarder status lines."""
    forwarded = 0
    for event in events:
        try:
            status_code, _ = post_event(event, target_url, timeout_seconds)
        except HTTPError as exc:
            print(
                f"{endpoint_label} rejected {rejected_label} with HTTP {exc.code}",
                file=sys.stderr,
            )
            continue
        except URLError as exc:
            print(f"Could not reach {unreachable_target}: {exc}", file=sys.stderr)
            continue
        if 200 <= status_code < 300:
            forwarded += 1
            print(success_message(event), flush=True)
        else:
            print(
                f"{endpoint_label} returned unexpected HTTP {status_code}",
                file=sys.stderr,
            )
    return forwarded


def follow_file(
    path: Path,
    *,
    from_start: bool,
    once: bool,
    poll_seconds: float,
    handle_line: Callable[[str], int],
) -> int:
    """Tail a file, handling missing files, truncation, and rotation."""
    forwarded = 0
    current_log: OpenLog | None = None
    initial_open = True
    try:
        while True:
            current_log = refresh_log_handle(
                path,
                current_log,
                from_start=from_start,
                initial_open=initial_open,
            )
            initial_open = False

            line = current_log.handle.readline()
            if line:
                forwarded += handle_line(line)
                current_log = current_log._replace(position=current_log.handle.tell())
                continue
            if once:
                return forwarded
            time.sleep(poll_seconds)
    finally:
        if current_log is not None:
            current_log.handle.close()


def refresh_log_handle(
    path: Path,
    current_log: OpenLog | None,
    *,
    from_start: bool,
    initial_open: bool,
) -> OpenLog:
    """Open or reopen a tailed file when it rotates or is truncated."""
    ensure_log_file(path)
    stat_result = path.stat()
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

    handle = path.open("r", encoding="utf-8")
    if initial_open and not from_start:
        handle.seek(0, os.SEEK_END)
    else:
        handle.seek(0)
    return OpenLog(handle=handle, identity=identity, position=handle.tell())


def ensure_log_file(path: Path) -> None:
    """Create a missing log file with permissive permissions for containers."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch()
    path.chmod(0o666)
