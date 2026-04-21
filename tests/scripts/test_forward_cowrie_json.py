from __future__ import annotations

import pytest

from scripts.forward_cowrie_json import (
    build_adapter_payload,
    follow_log_file,
    iter_json_events,
    normalize_event,
)


pytestmark = pytest.mark.unit


def test_iter_json_events_skips_invalid_lines() -> None:
    events = list(
        iter_json_events(
            [
                "\n",
                '{"eventid": "cowrie.login.failed", "src_ip": "198.51.100.1"}\n',
                "not-json\n",
                "[1, 2, 3]\n",
            ]
        )
    )

    assert events == [
        {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.1"}
    ]


def test_build_adapter_payload_wraps_event_and_protocol() -> None:
    event = {"eventid": "cowrie.command.input", "input": "id"}

    payload = build_adapter_payload(event, protocol="ssh")

    assert payload == {"event": event, "protocol": "ssh"}


def test_normalize_event_converts_structured_message() -> None:
    event = {"eventid": "cowrie.session.params", "message": []}

    normalized = normalize_event(event)

    assert normalized == {"eventid": "cowrie.session.params", "message": "[]"}


def test_normalize_event_skips_empty_command_input() -> None:
    event = {"eventid": "cowrie.command.input", "input": "  "}

    normalized = normalize_event(event)

    assert normalized is None


def test_follow_log_file_creates_missing_file_in_tail_mode(tmp_path) -> None:
    log_file = tmp_path / "log" / "cowrie" / "cowrie.json"

    forwarded = follow_log_file(
        log_file=log_file,
        adapter_url="http://127.0.0.1:9/v1/cowrie/events",
        protocol="ssh",
        from_start=False,
        once=True,
        poll_seconds=0.0,
        timeout_seconds=0.01,
    )

    assert forwarded == 0
    assert log_file.exists()
