from __future__ import annotations

from libs.contracts.models import HighInteractionIngestRequest, HighInteractionLogEvent
from services.binding_service.domain import BindingService
from services.high_interaction.domain import HighInteractionService
from services.profiler.domain import ProfilerService
from tests.support.attack_catalog import build_test_attack_catalog
from tests.support.inmemory_repositories import InMemoryBindingRepository
from tests.support.inmemory_repositories import InMemoryEvidenceRepository
from tests.support.inmemory_repositories import InMemoryHighInteractionObservationRepository
from tests.support.inmemory_repositories import InMemoryProfileRepository


def _service() -> tuple[HighInteractionService, InMemoryHighInteractionObservationRepository]:
    repository = InMemoryHighInteractionObservationRepository()
    service = HighInteractionService(
        BindingService(InMemoryBindingRepository()),
        ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
        repository,
    )
    return service, repository


def test_conpot_modbus_probe_updates_profile_with_asset_reference() -> None:
    service, repository = _service()

    response = service.ingest(
        HighInteractionIngestRequest(
            event=HighInteractionLogEvent(
                source="conpot",
                asset_id="conpot-plc",
                attacker_key="198.51.100.44",
                service="modbus",
                event_type="modbus.read",
                logdata={"function": "Read Holding Registers"},
            )
        )
    )

    observations = tuple(repository.list_recent())
    assert observations[0].asset_id == "conpot-plc"
    assert "T1046" in response.profile.recent_techniques
    assert "T1005" in response.profile.recent_techniques
    assert response.observation.profiler_evidence_ids


def test_dionaea_download_maps_to_transfer_and_execution() -> None:
    service, _repository = _service()

    response = service.ingest(
        HighInteractionIngestRequest(
            event=HighInteractionLogEvent(
                source="dionaea",
                asset_id="dionaea-capture",
                attacker_key="198.51.100.45",
                service="http",
                event_type="download.offer",
                logdata={"url": "/downloads/agent-update.bin", "payload": "agent-update.bin"},
            )
        )
    )

    assert "T1190" in response.profile.recent_techniques
    assert "T1204.002" in response.profile.recent_techniques
    assert "T1105" in response.profile.recent_techniques


def test_honeytrap_payload_probe_maps_to_generic_capture() -> None:
    service, _repository = _service()

    response = service.ingest(
        HighInteractionIngestRequest(
            event=HighInteractionLogEvent(
                source="honeytrap",
                asset_id="honeytrap-generic",
                attacker_key="198.51.100.46",
                service="tcp",
                event_type="payload.transfer",
                logdata={"message": "binary payload upload"},
            )
        )
    )

    assert "T1046" in response.profile.recent_techniques
    assert "T1190" in response.profile.recent_techniques
    assert "T1105" in response.profile.recent_techniques

