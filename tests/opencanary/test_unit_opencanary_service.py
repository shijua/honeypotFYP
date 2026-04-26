from __future__ import annotations

from datetime import datetime, timezone

import pytest

from libs.contracts.models import OpenCanaryIngestRequest, OpenCanaryLogEvent
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.opencanary.domain import OpenCanaryService
from services.opencanary.repository import InMemoryOpenCanaryObservationRepository
from services.profiler.domain import ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def _service() -> tuple[OpenCanaryService, InMemoryOpenCanaryObservationRepository]:
    repository = InMemoryOpenCanaryObservationRepository()
    return (
        OpenCanaryService(
            BindingService(InMemoryBindingRepository()),
            ProfilerService(
                InMemoryEvidenceRepository(),
                InMemoryProfileRepository(),
                build_test_attack_catalog(),
            ),
            repository,
        ),
        repository,
    )


def test_redis_probe_maps_to_network_service_discovery() -> None:
    service, repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.30",
                src_port=53000,
                dst_host="146.169.44.23",
                dst_port=6380,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logtype=5001,
                node_id="opencanary-entrypoint-01",
                logdata={"SERVICE": "redis", "COMMAND": "INFO"},
            )
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.service == "redis"
    assert observation.tags[:2] == ["mitre_discovery", "T1046"]
    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1046"]


def test_login_probe_maps_to_credential_access_without_storing_password() -> None:
    service, repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.31",
                dst_port=2224,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "ssh",
                    "USERNAME": "root",
                    "PASSWORD": "letmein",
                },
            ),
            protocol="ssh",
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.username == "root"
    assert observation.password_seen is True
    assert observation.logdata["PASSWORD"] == "[redacted]"
    assert "letmein" not in str(observation.model_dump())
    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1110"]

