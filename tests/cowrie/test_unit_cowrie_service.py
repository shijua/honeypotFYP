from __future__ import annotations

from datetime import datetime, timezone

import pytest

from libs.contracts.models import CowrieIngestRequest, CowrieLogEvent
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.cowrie.domain import CowrieService
from services.cowrie.event_catalog import FileCowrieEventCatalog
from services.cowrie.repository import InMemoryCowrieObservationRepository
from services.profiler.domain import ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def _service() -> tuple[CowrieService, InMemoryCowrieObservationRepository]:
    repository = InMemoryCowrieObservationRepository()
    return (
        CowrieService(
            BindingService(InMemoryBindingRepository()),
            ProfilerService(
                InMemoryEvidenceRepository(),
                InMemoryProfileRepository(),
                build_test_attack_catalog(),
            ),
            repository,
            FileCowrieEventCatalog("data/cowrie/event_mappings.json"),
        ),
        repository,
    )


def test_failed_login_maps_to_credential_access_without_storing_password() -> None:
    service, repository = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.login.failed",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.210",
                session="s-1",
                username="root",
                password="123456",
            )
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.password_seen is True
    assert "password" not in observation.model_dump()
    assert len(observation.profiler_evidence_ids) == 1
    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1110"]


def test_command_input_maps_to_execution() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.211",
                session="s-2",
                input="uname -a",
            )
        )
    )

    assert response.observation.command == "uname -a"
    assert len(response.observation.profiler_evidence_ids) == 1
    assert response.profile.recent_tactics == ["Execution"]
    assert response.profile.recent_techniques == ["T1059"]


def test_successful_login_stays_descriptive_without_attack_mapping() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.login.success",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.212",
                session="s-3",
                username="admin",
            )
        )
    )

    assert response.observation.tags == ["cowrie_auth_success"]
    assert response.observation.profiler_evidence_ids == []
    assert response.profile.recent_tactics == []
    assert response.profile.recent_techniques == []


def test_client_metadata_stays_descriptive_without_attack_mapping() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.client.version",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.213",
                session="s-4",
                version="SSH-2.0-libssh_0.9.6",
            )
        )
    )

    assert response.observation.tags == ["cowrie_client_metadata"]
    assert response.observation.profiler_evidence_ids == []
    assert response.profile.recent_tactics == []
    assert response.profile.recent_techniques == []
