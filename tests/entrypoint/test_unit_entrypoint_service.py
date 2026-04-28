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
    assert observations[0].matched_rules == ["public_http_login_attempt"]
    assert "body_preview:pwd=" in observations[0].indicators
    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1110"]


def test_capture_http_request_maps_public_secret_probe_to_credential_access() -> None:
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
            attacker_key="198.51.100.201",
            method="GET",
            path="/.env.old",
            headers={"user-agent": "curl/8.0"},
        )
    )

    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1552.001"]


def test_capture_http_request_maps_source_map_probe_to_discovery() -> None:
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
            attacker_key="198.51.100.202",
            method="GET",
            path="/assets/app.js.map",
            headers={"user-agent": "gobuster/3.6"},
        )
    )

    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1046"]
    observations = tuple(observation_repository.list_recent())
    assert observations[0].matched_rules == ["public_http_web_discovery"]
    assert "user_agent:gobuster" in observations[0].indicators
    assert "path:.map" in observations[0].indicators
