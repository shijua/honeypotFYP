from __future__ import annotations

import pytest

from libs.contracts.models import EntrypointCaptureRequest
from services.binding_service.domain import BindingService
from tests.support.inmemory_repositories import InMemoryBindingRepository
from services.entrypoint.domain import EntrypointService
from tests.support.inmemory_repositories import InMemoryEntrypointObservationRepository
from services.profiler.domain import ProfilerService
from tests.support.inmemory_repositories import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def test_capture_http_request_creates_binding_and_observation_without_profile_evidence() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        observation_repository,
        profiler_service=ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
    )

    response = service.capture_http_request(
        EntrypointCaptureRequest(
            attacker_key="198.51.100.200",
            method="POST",
            path="/contact",
            query_string="",
            headers={
                "user-agent": "curl/8.0",
                "authorization": "Bearer secret",
            },
            body_preview="message=hello",
        )
    )

    observations = tuple(observation_repository.list_recent())
    assert len(observations) == 1
    assert observations[0].binding_id == response.binding.binding_id
    assert observations[0].headers["authorization"] == "[redacted]"
    assert observations[0].body_preview == "message=hello"
    assert observations[0].profiler_evidence_ids == []
    assert observations[0].matched_rules == []
    assert observations[0].indicators == []
    assert response.profile.attacker_key == "198.51.100.200"
    assert response.profile.recent_tactics == []
    assert response.profile.recent_techniques == []


def test_capture_http_request_profiles_public_secret_probe() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        observation_repository,
        profiler_service=ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
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
    observations = tuple(observation_repository.list_recent())
    assert observations[0].path == "/.env.old"
    assert observations[0].matched_rules == ["public_http_credential_discovery"]
    assert "combined:.env" in observations[0].indicators
    assert observations[0].profiler_evidence_ids


def test_capture_http_request_profiles_source_map_probe() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        observation_repository,
        profiler_service=ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
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
    assert "path:.map" in observations[0].indicators


def test_capture_http_request_profiles_internal_artifact_access() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        observation_repository,
        profiler_service=ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
    )

    response = service.capture_http_request(
        EntrypointCaptureRequest(
            attacker_key="198.51.100.203",
            method="GET",
            path="/finance/archive/2024/payroll-archive.zip",
            headers={"user-agent": "curl/8.0"},
            surface="internal",
            asset_id="finance-share",
        )
    )

    assert response.profile.recent_tactics == ["Collection"]
    assert response.profile.recent_techniques == ["T1005"]
    assert response.profile.recent_internal_http_paths == [
        "/finance/archive/2024/payroll-archive.zip"
    ]
    observations = tuple(observation_repository.list_recent())
    assert observations[0].surface == "internal"
    assert observations[0].asset_id == "finance-share"
    assert observations[0].matched_rules == ["internal_http_artifact_access"]


def test_capture_http_request_profiles_internal_token_reuse() -> None:
    observation_repository = InMemoryEntrypointObservationRepository()
    service = EntrypointService(
        BindingService(InMemoryBindingRepository()),
        observation_repository,
        profiler_service=ProfilerService(
            InMemoryEvidenceRepository(),
            InMemoryProfileRepository(),
            build_test_attack_catalog(),
        ),
    )

    response = service.capture_http_request(
        EntrypointCaptureRequest(
            attacker_key="198.51.100.204",
            method="POST",
            path="/session",
            headers={"user-agent": "curl/8.0"},
            body_preview="username=portal.reader&token=nbp_reader_2026_04_window&auth_result=success",
            surface="internal",
            asset_id="internal-portal",
        )
    )

    assert response.profile.recent_tactics == [
        "Credential Access",
        "Lateral Movement",
        "Defense Evasion",
    ]
    assert response.profile.recent_techniques == ["T1110", "T1021", "T1078"]
    observations = tuple(observation_repository.list_recent())
    assert observations[0].body_preview == "username=portal.reader&token=[redacted]&auth_result=success"
    assert observations[0].matched_rules == [
        "internal_http_login_attempt",
        "internal_http_valid_token_reuse",
    ]
