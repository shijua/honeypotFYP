from __future__ import annotations

import pytest

from scripts import forward_public_portal_access_log as forwarder
from scripts.forward_public_portal_access_log import (
    follow_log_file,
    iter_access_events,
    parse_access_line,
    should_profile_public_request,
)


pytestmark = pytest.mark.unit


def test_parse_access_line_builds_entrypoint_event() -> None:
    event = parse_access_line(
        '198.51.100.10 - - [26/Apr/2026:12:00:00 +0000] '
        '"GET /.env.old?backup=1 HTTP/1.1" 404 153 "-" "curl/8.0"\n'
    )

    assert event == {
        "attacker_key": "198.51.100.10",
        "method": "GET",
        "path": "/.env.old",
        "query_string": "backup=1",
        "headers": {"user-agent": "curl/8.0"},
        "body_preview": None,
        "body_truncated": False,
        "protocol": "http",
    }


def test_should_profile_public_request_classifies_suspicious_paths_and_tools() -> None:
    assert should_profile_public_request("/.env.old")
    assert should_profile_public_request("/assets/app.js.map")
    assert should_profile_public_request("/", "gobuster/3.6")
    assert not should_profile_public_request("/docs", "Mozilla/5.0")


def test_iter_access_events_skips_bad_lines_and_normal_public_pages() -> None:
    events = list(
        iter_access_events(
            [
                "\n",
                "not nginx\n",
                '203.0.113.8 - - [26/Apr/2026:12:00:00 +0000] "GET /robots.txt HTTP/1.1" 200 12 "-" "curl/8.0"\n',
                '203.0.113.8 - - [26/Apr/2026:12:00:01 +0000] "GET /.env.old HTTP/1.1" 404 12 "-" "curl/8.0"\n',
            ]
        )
    )

    assert len(events) == 1
    assert events[0]["path"] == "/.env.old"


def test_forward_lines_posts_public_portal_events(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def _post_event(
        payload: dict[str, object],
        observer_url: str,
        timeout_seconds: float,
    ) -> tuple[int, str]:
        calls.append(payload)
        return 200, "{}"

    monkeypatch.setattr(forwarder, "post_event", _post_event)

    forwarded = forwarder.forward_lines(
        [
            '198.51.100.10 - - [26/Apr/2026:12:00:00 +0000] "GET /docs HTTP/1.1" 200 1 "-" "Mozilla/5.0"\n',
            '198.51.100.10 - - [26/Apr/2026:12:00:01 +0000] "GET /assets/app.js.map HTTP/1.1" 404 1 "-" "sqlmap/1.8"\n',
        ],
        observer_url="http://127.0.0.1:8010/v1/entrypoint/events",
        timeout_seconds=0.01,
    )

    assert forwarded == 1
    assert calls[0]["path"] == "/assets/app.js.map"
    assert calls[0]["headers"] == {"user-agent": "sqlmap/1.8"}


def test_follow_log_file_creates_missing_file_in_tail_mode(tmp_path) -> None:
    log_file = tmp_path / "nginx" / "access.log"

    forwarded = follow_log_file(
        log_file=log_file,
        observer_url="http://127.0.0.1:9/v1/entrypoint/events",
        from_start=False,
        once=True,
        poll_seconds=0.0,
        timeout_seconds=0.01,
    )

    assert forwarded == 0
    assert log_file.exists()
