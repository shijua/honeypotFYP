from __future__ import annotations

from datetime import datetime, timezone

import pytest

from libs.contracts.models import CowrieIngestRequest, CowrieLogEvent
from services.binding_service.domain import BindingService
from tests.support.inmemory_repositories import InMemoryBindingRepository
from services.cowrie.command_mapping import FileCowrieCommandRuleCatalog
from services.cowrie.domain import CowrieService
from services.cowrie.event_catalog import FileCowrieEventCatalog
from tests.support.inmemory_repositories import InMemoryCowrieObservationRepository
from services.profiler.domain import ProfilerService
from tests.support.inmemory_repositories import InMemoryEvidenceRepository, InMemoryProfileRepository
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
            FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json"),
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


def test_unmapped_command_input_is_observation_only() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.211",
                session="s-2",
                input="totallycustom",
            )
        )
    )

    assert response.observation.command == "totallycustom"
    assert response.observation.tags == ["cowrie_command_input"]
    assert response.observation.profiler_evidence_ids == []
    assert response.profile.recent_tactics == []
    assert response.profile.recent_techniques == []


def test_command_input_adds_data_driven_discovery_mapping() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.214",
                session="s-5",
                input="ls -la /tmp",
            )
        )
    )

    assert len(response.observation.profiler_evidence_ids) == 1
    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1083"]


def test_failed_command_is_observation_only_to_avoid_duplicate_profile_evidence() -> None:
    service, repository = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.failed",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.215",
                session="s-6",
                input="nmap 10.0.0.0/24",
            )
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.command == "nmap 10.0.0.0/24"
    assert observation.tags == ["cowrie_command_failed"]
    assert observation.profiler_evidence_ids == []
    assert response.profile.recent_tactics == []
    assert response.profile.recent_techniques == []


def test_command_input_then_failed_does_not_double_count_same_command() -> None:
    service, repository = _service()

    first_response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.217",
                session="s-8",
                input="nmap 10.0.0.0/24",
            )
        )
    )
    second_response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.failed",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.217",
                session="s-8",
                input="nmap 10.0.0.0/24",
            )
        )
    )

    observations = tuple(repository.list_recent())
    assert len(first_response.observation.profiler_evidence_ids) == 1
    assert observations[0].eventid == "cowrie.command.input"
    assert observations[1].eventid == "cowrie.command.failed"
    assert observations[1].profiler_evidence_ids == []
    assert second_response.profile.recent_tactics == ["Discovery"]
    assert second_response.profile.recent_techniques == ["T1046"]


def test_command_mapping_can_use_elastic_derived_credential_rule() -> None:
    service, _ = _service()

    response = service.ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.216",
                session="s-7",
                input="grep password /app/.env",
            )
        )
    )

    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1552.001"]


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
