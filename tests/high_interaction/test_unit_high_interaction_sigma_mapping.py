from __future__ import annotations

from libs.contracts.models import HighInteractionLogEvent
from services.high_interaction.sigma_mapping import FileHighInteractionSigmaRuleMatcher


def _matcher() -> FileHighInteractionSigmaRuleMatcher:
    return FileHighInteractionSigmaRuleMatcher("data/detections/high_interaction_sigma")


def test_conpot_modbus_event_matches_ics_collection_rule() -> None:
    tags = _matcher().tags_for(
        HighInteractionLogEvent(
            source="conpot",
            asset_id="conpot-plc",
            attacker_key="198.51.100.44",
            service="modbus",
            event_type="modbus.read",
            logdata={"function": "Read Holding Registers", "unit": "plc-7"},
        )
    )

    assert "T1046" in tags
    assert "T1005" in tags
    assert "T1021" in tags


def test_dionaea_download_event_matches_payload_transfer_rule() -> None:
    tags = _matcher().tags_for(
        HighInteractionLogEvent(
            source="dionaea",
            asset_id="dionaea-capture",
            attacker_key="198.51.100.45",
            service="http",
            event_type="download.offer",
            logdata={"url": "/downloads/agent-update.bin", "message": "payload download"},
        )
    )

    assert "T1190" in tags
    assert "T1204.002" in tags
    assert "T1105" in tags
    assert "T1041" in tags


def test_honeytrap_payload_event_matches_generic_capture_rule() -> None:
    tags = _matcher().tags_for(
        HighInteractionLogEvent(
            source="honeytrap",
            asset_id="honeytrap-generic",
            attacker_key="198.51.100.46",
            service="tcp",
            event_type="payload.transfer",
            logdata={"message": "binary payload upload"},
        )
    )

    assert "T1046" in tags
    assert "T1190" in tags
    assert "T1105" in tags
