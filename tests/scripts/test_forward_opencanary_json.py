from __future__ import annotations

import pytest

from scripts.forwarders import opencanary_json as forwarder
from scripts.forwarders.opencanary_json import (
    attribute_asset_gateway_source,
    build_adapter_payload,
    follow_log_file,
    load_asset_gateway_routes,
    normalize_event,
    _refresh_log_handle,
)


pytestmark = pytest.mark.unit


def test_build_adapter_payload_wraps_event_and_protocol() -> None:
    event = {"src_host": "198.51.100.1", "dst_port": 9418}

    payload = build_adapter_payload(event, protocol="git")

    assert payload == {"event": event, "protocol": "git"}


def test_normalize_event_skips_missing_source_host() -> None:
    assert normalize_event({"dst_port": 6379}) is None


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
        ['{"src_host": "198.51.100.2", "dst_port": 80}\n', '{"dst_port": 80}\n'],
        adapter_url="http://127.0.0.1:8012/v1/opencanary/events",
        protocol="http",
        timeout_seconds=0.01,
    )

    assert forwarded == 1
    assert calls == [
        {
            "event": {"src_host": "198.51.100.2", "dst_port": 80, "logdata": {}},
            "protocol": "http",
        }
    ]


def test_asset_gateway_routes_restore_original_attacker_ip(tmp_path) -> None:
    route_file = tmp_path / "asset_gateway_routes.json"
    route_file.write_text(
        """
        {
          "routes": [
            {
              "attacker_key": "198.51.100.77",
              "asset_id": "redis-cache",
              "public_port": 16379,
              "backend_host": "honeynet-abcd-redis-cache",
              "backend_ip": "172.25.0.5",
              "backend_port": 6379
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    event = {
        "src_host": "172.25.0.3",
        "dst_host": "172.25.0.5",
        "dst_port": 6379,
        "logdata": {"CMD": "INFO"},
    }

    attributed = attribute_asset_gateway_source(
        event,
        load_asset_gateway_routes(route_file),
    )

    assert attributed["src_host"] == "198.51.100.77"
    assert attributed["logdata"]["ASSET_GATEWAY_PROXY_SRC_HOST"] == "172.25.0.3"
    assert attributed["logdata"]["ASSET_ID"] == "redis-cache"
    assert attributed["logdata"]["ASSET_GATEWAY_PUBLIC_PORT"] == 16379


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
        asset_routes_file=None,
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
