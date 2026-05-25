from __future__ import annotations

from scripts.forwarders.high_interaction_logs import build_adapter_payload, forward_lines


def test_build_adapter_payload_normalizes_json_event_with_source_ip() -> None:
    payload = build_adapter_payload(
        {
            "src_ip": "198.51.100.10",
            "dst_port": 80,
            "message": "payload download",
        },
        source="dionaea",
        asset_id="dionaea-capture",
        service="http",
        event_type="download.offer",
        protocol="tcp",
        asset_routes=[],
    )

    assert payload is not None
    event = payload["event"]
    assert isinstance(event, dict)
    assert event["source"] == "dionaea"
    assert event["asset_id"] == "dionaea-capture"
    assert event["attacker_key"] == "198.51.100.10"
    assert event["service"] == "http"
    assert event["logdata"] == {"message": "payload download"}


def test_build_adapter_payload_can_attribute_source_from_asset_route() -> None:
    payload = build_adapter_payload(
        {
            "dst_host": "172.25.0.40",
            "dst_port": 445,
            "event_type": "smb.probe",
        },
        source="dionaea",
        asset_id="dionaea-capture",
        service="smb",
        event_type="tcp.probe",
        protocol="tcp",
        asset_routes=[
            {
                "asset_id": "dionaea-capture",
                "attacker_key": "198.51.100.11",
                "backend_ip": "172.25.0.40",
                "backend_port": 445,
            }
        ],
    )

    assert payload is not None
    event = payload["event"]
    assert isinstance(event, dict)
    assert event["attacker_key"] == "198.51.100.11"


def test_forward_lines_posts_high_interaction_payload(monkeypatch) -> None:
    posted: list[dict[str, object]] = []

    def fake_post(payload: dict[str, object], target_url: str, timeout_seconds: float) -> tuple[int, str]:
        posted.append(payload)
        return 200, "{}"

    monkeypatch.setattr("scripts.forwarders.high_interaction_logs.post_event", fake_post)

    count = forward_lines(
        ['{"src_ip":"198.51.100.12","message":"payload upload"}'],
        adapter_url="http://adapter/v1/high-interaction/events",
        source="honeytrap",
        asset_id="honeytrap-generic",
        service="tcp",
        event_type="payload.transfer",
        protocol="tcp",
        timeout_seconds=1,
    )

    assert count == 1
    event = posted[0]["event"]
    assert isinstance(event, dict)
    assert event["source"] == "honeytrap"
    assert event["attacker_key"] == "198.51.100.12"
