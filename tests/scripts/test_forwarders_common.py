from __future__ import annotations

import pytest

from scripts.forwarders.common import iter_json_objects, payload_event


pytestmark = pytest.mark.unit


def test_iter_json_objects_skips_invalid_lines() -> None:
    events = list(
        iter_json_objects(
            [
                "\n",
                '{"eventid": "cowrie.login.failed", "src_ip": "198.51.100.1"}\n',
                "not-json\n",
                "[1, 2, 3]\n",
            ],
            label="test JSON",
        )
    )

    assert events == [
        {"eventid": "cowrie.login.failed", "src_ip": "198.51.100.1"}
    ]


def test_payload_event_returns_nested_event_only() -> None:
    assert payload_event({"event": {"source": "cowrie"}}) == {"source": "cowrie"}
    assert payload_event({"event": []}) == {}
