from __future__ import annotations

import pytest

from libs.contracts.models import EntrypointCaptureRequest
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.entrypoint.domain import EntrypointService
from services.entrypoint.repository import InMemoryEntrypointObservationRepository
from services.profiler.domain import ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def test_capture_http_request_creates_binding_observation_and_profile_evidence() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
        observation_repository,
    )

    response = service.capture_http_request(
        EntrypointCaptureRequest(
            attacker_key="198.51.100.200",
            method="POST",
            path="/wp-login.php",
            query_string="redirect_to=/wp-admin",
            headers={
                "user-agent": "curl/8.0",
                "authorization": "Bearer secret",
            },
            body_preview="log=admin&pwd=hunter2",
        )
    )

    observations = tuple(observation_repository.list_recent())
    assert len(observations) == 1
    assert observations[0].binding_id == response.binding.binding_id
    assert observations[0].headers["authorization"] == "[redacted]"
    assert observations[0].body_preview == "log=admin&pwd=[redacted]"
    assert observations[0].profiler_evidence_ids == response.profile.recent_evidence_ids
    assert response.profile.conf_by_tactic == {}
