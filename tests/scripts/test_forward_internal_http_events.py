from __future__ import annotations

import json

from scripts.forwarders import internal_http_events as forwarder


def test_forward_internal_http_events_posts_jsonl_payload(
    monkeypatch,
) -> None:
    posted: list[tuple[dict[str, object], str, float]] = []

    def _post_event(
        payload: dict[str, object],
        observer_url: str,
        timeout_seconds: float,
    ) -> tuple[int, str]:
        posted.append((payload, observer_url, timeout_seconds))
        return 200, "{}"

    monkeypatch.setattr(forwarder, "post_event", _post_event)

    forwarded = forwarder.forward_lines(
        [
            json.dumps(
                {
                    "attacker_key": "198.51.100.10",
                    "asset_id": "finance-share",
                    "method": "GET",
                    "path": "/finance/archive/2024/payroll-archive.zip",
                    "protocol": "http",
                    "surface": "internal",
                }
            )
        ],
        observer_url="http://entrypoint-observer:8010/v1/entrypoint/events",
        timeout_seconds=1.0,
    )

    assert forwarded == 1
    assert posted[0][0]["surface"] == "internal"
    assert posted[0][0]["asset_id"] == "finance-share"
    assert posted[0][0]["path"] == "/finance/archive/2024/payroll-archive.zip"


def test_forward_internal_http_events_skips_invalid_lines() -> None:
    forwarded = forwarder.forward_lines(
        ["not-json\n", "[]\n", "\n"],
        observer_url="http://entrypoint-observer:8010/v1/entrypoint/events",
        timeout_seconds=1.0,
    )

    assert forwarded == 0
