from __future__ import annotations

import pytest

from scripts import forward_opencanary_json as forwarder
from scripts.forward_opencanary_json import (
    build_adapter_payload,
    follow_log_file,
    iter_json_events,
    normalize_event,
    _refresh_log_handle,
)


pytestmark = pytest.mark.unit


def test_iter_json_events_skips_invalid_lines() -> None:
    events = list(
        iter_json_events(
            [
                "\n",
                '{"src_host": "198.51.100.1", "dst_port": 6380}\n',
                "not-json\n",
                "[1, 2, 3]\n",
            ]
        )
    )

    assert events == [{"src_host": "198.51.100.1", "dst_port": 6380}]


def test_build_adapter_payload_wraps_event_and_protocol() -> None:
    event = {"src_host": "198.51.100.1", "dst_port": 9418}

    payload = build_adapter_payload(event, protocol="git")

    assert payload == {"event": event, "protocol": "git"}


def test_normalize_event_skips_missing_source_host() -> None:
    assert normalize_event({"dst_port": 6380}) is None


def test_normalize_event_converts_structured_logdata() -> None:
    event = {"src_host": "198.51.100.1", "logdata": ["hello"]}

    normalized = normalize_event(event)

    assert normalized == {
        "src_host": "198.51.100.1",
        "logdata": {"message": "[\"hello\"]"},
    }


def test_forward_lines_posts_normalized_events(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def _post_event(
        payload: dict[str, object],
        adapter_url: str,
        timeout_seconds: float,
    ) -> tuple[int, str]:
        calls.append(payload)
        return 200, "{}"

    monkeypatch.setattr(forwarder, "post_event", _post_event)

    forwarded = forwarder.forward_lines(
        ['{"src_host": "198.51.100.2", "dst_port": 8082}\n', '{"dst_port": 8082}\n'],
        adapter_url="http://127.0.0.1:8012/v1/opencanary/events",
        protocol="http",
        timeout_seconds=0.01,
    )

    assert forwarded == 1
    assert calls == [
        {
            "event": {"src_host": "198.51.100.2", "dst_port": 8082, "logdata": {}},
            "protocol": "http",
        }
    ]


def test_follow_log_file_creates_missing_file_in_tail_mode(tmp_path) -> None:
    log_file = tmp_path / "opencanary" / "opencanary.log"

    forwarded = follow_log_file(
        log_file=log_file,
        adapter_url="http://127.0.0.1:9/v1/opencanary/events",
        protocol="tcp",
        from_start=False,
        once=True,
        poll_seconds=0.0,
        timeout_seconds=0.01,
    )

    assert forwarded == 0
    assert log_file.exists()


def test_refresh_log_handle_reopens_after_rotation(tmp_path) -> None:
    log_file = tmp_path / "opencanary.log"
    log_file.write_text('{"src_host": "old"}\n', encoding="utf-8")
    current = _refresh_log_handle(
        log_file,
        None,
        from_start=False,
        initial_open=True,
    )
    assert current.position == len(log_file.read_text(encoding="utf-8"))

    log_file.unlink()
    log_file.write_text('{}\n', encoding="utf-8")

    reopened = _refresh_log_handle(
        log_file,
        current,
        from_start=False,
        initial_open=False,
    )
    try:
        assert reopened.identity != current.identity
        assert reopened.position == 0
        assert reopened.handle.readline().strip() == "{}"
    finally:
        reopened.handle.close()

