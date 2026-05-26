from __future__ import annotations

from datetime import datetime, timezone

import pytest

from libs.contracts.models import OpenCanaryIngestRequest, OpenCanaryLogEvent
from services.binding_service.domain import BindingService
from tests.support.inmemory_repositories import InMemoryBindingRepository
from services.opencanary.domain import OpenCanaryService
from tests.support.inmemory_repositories import InMemoryOpenCanaryObservationRepository
from services.profiler.domain import ProfilerService
from tests.support.inmemory_repositories import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def _service() -> tuple[
    OpenCanaryService,
    InMemoryOpenCanaryObservationRepository,
    InMemoryEvidenceRepository,
]:
    repository = InMemoryOpenCanaryObservationRepository()
    evidence_repository = InMemoryEvidenceRepository()
    return (
        OpenCanaryService(
            BindingService(InMemoryBindingRepository()),
            ProfilerService(
                evidence_repository,
                InMemoryProfileRepository(),
                build_test_attack_catalog(),
            ),
            repository,
        ),
        repository,
        evidence_repository,
    )


def test_redis_probe_maps_to_network_service_discovery() -> None:
    service, repository, _evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.30",
                src_port=53000,
                dst_host="146.169.44.23",
                dst_port=6379,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logtype=5001,
                node_id="opencanary-internal-redis",
                logdata={"SERVICE": "redis", "COMMAND": "INFO"},
            )
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.service == "redis"
    assert observation.tags[:2] == ["mitre_discovery", "T1046"]
    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1046"]


def test_redis_key_lookup_adds_collection_context() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.30",
                src_port=53000,
                dst_host="146.169.44.23",
                dst_port=6379,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logtype=17001,
                node_id="opencanary-internal-redis",
                logdata={"SERVICE": "redis", "COMMAND": "KEYS"},
            )
        )
    )

    assert response.profile.recent_tactics == ["Discovery", "Collection"]
    assert response.profile.recent_techniques == ["T1046", "T1213"]
    evidences = evidence_repository.list_by_attacker("198.51.100.30")
    assert evidences[1].source_ref["opencanary_command"] == "KEYS"


def test_login_probe_maps_to_credential_access_without_storing_password() -> None:
    service, repository, _evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.31",
                dst_port=22,
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
    assert response.profile.recent_tactics == ["Credential Access", "Lateral Movement"]
    assert response.profile.recent_techniques == ["T1110", "T1021", "T1021.004"]


@pytest.mark.parametrize(
    ("service_name", "dst_port", "logtype"),
    [
        ("ftp", 21, 2000),
        ("telnet", 23, 6001),
    ],
)
def test_interactive_login_probe_maps_to_credential_and_lateral_context(
    service_name: str,
    dst_port: int,
    logtype: int,
) -> None:
    service, _repository, _evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.34",
                dst_port=dst_port,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logtype=logtype,
                logdata={
                    "SERVICE": service_name,
                    "USERNAME": "operator",
                    "PASSWORD": "WrongPassword",
                },
            ),
        )
    )

    assert response.profile.recent_tactics == ["Credential Access", "Lateral Movement"]
    assert response.profile.recent_techniques == ["T1110", "T1021"]


def test_ftp_upload_maps_to_exfiltration_without_login_tags() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.37",
                dst_port=21,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "ftp",
                    "COMMAND": "STOR finance-drop.zip",
                },
            ),
            protocol="ftp",
        )
    )

    assert response.profile.recent_techniques == ["T1567.002"]
    evidences = evidence_repository.list_by_attacker("198.51.100.37")
    assert evidences[0].source_ref["opencanary_command"] == "STOR"


def test_ftp_download_maps_to_collection_without_exfiltration_tags() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.38",
                dst_port=21,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "ftp",
                    "COMMAND": "RETR finance-drop.zip",
                },
            ),
            protocol="ftp",
        )
    )

    assert response.profile.recent_techniques == ["T1039"]
    evidences = evidence_repository.list_by_attacker("198.51.100.38")
    assert evidences[0].source_ref["opencanary_command"] == "RETR"


def test_mysql_login_probe_maps_to_credential_access() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.35",
                dst_port=3306,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logtype=8001,
                logdata={
                    "SERVICE": "mysql",
                    "USERNAME": "backup_reader",
                    "PASSWORD": "WrongPassword",
                },
            ),
            protocol="mysql",
        )
    )

    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1110"]
    evidences = evidence_repository.list_by_attacker("198.51.100.35")
    assert evidences[0].source_ref["opencanary_service"] == "mysql"


def test_smtp_probe_maps_to_smtp_discovery() -> None:
    service, repository, _evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.32",
                dst_port=25,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "smtp",
                    "COMMANDS": ["HELO", "QUIT"],
                },
            ),
            protocol="smtp",
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.service == "smtp"
    assert observation.tags == [
        "mitre_discovery",
        "T1046",
        "opencanary",
        "opencanary_smtp",
    ]
    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1046"]


def test_smtp_recipient_probe_maps_to_email_account_discovery() -> None:
    service, repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.39",
                dst_port=25,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "smtp",
                    "COMMANDS": ["VRFY finance"],
                },
            ),
            protocol="smtp",
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.service == "smtp"
    assert response.profile.recent_tactics == ["Discovery"]
    assert response.profile.recent_techniques == ["T1087.003"]
    evidences = evidence_repository.list_by_attacker("198.51.100.39")
    assert evidences[0].source_ref["opencanary_commands"] == ["VRFY"]


def test_smtp_auth_probe_maps_to_credential_access() -> None:
    service, repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.36",
                dst_port=25,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "smtp",
                    "COMMANDS": ["EHLO", "AUTH", "QUIT"],
                    "PASSWORD": "[redacted]",
                },
            ),
            protocol="smtp",
        )
    )

    observation = tuple(repository.list_recent())[0]
    assert observation.password_seen is True
    assert observation.logdata["PASSWORD"] == "[redacted]"
    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1110"]
    evidences = evidence_repository.list_by_attacker("198.51.100.36")
    assert evidences[0].source_ref["opencanary_commands"] == ["EHLO", "AUTH", "QUIT"]


def test_smtp_auth_and_recipient_probe_keep_both_contexts() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.40",
                dst_port=25,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "smtp",
                    "COMMANDS": ["EHLO tester", "VRFY finance", "AUTH LOGIN"],
                    "ASSET_ID": "mail-relay",
                },
            ),
            protocol="smtp",
        )
    )

    assert response.profile.recent_tactics == ["Credential Access", "Discovery"]
    assert response.profile.recent_techniques == ["T1110", "T1087.003"]
    evidences = evidence_repository.list_by_attacker("198.51.100.40")
    assert evidences[0].source_ref["asset_id"] == "mail-relay"


def test_git_probe_adds_collection_context() -> None:
    service, _repository, evidence_repository = _service()

    response = service.ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host="198.51.100.33",
                dst_port=9418,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                logdata={
                    "SERVICE": "git",
                    "REPO": "infra-deploy.git",
                },
            ),
            protocol="git",
        )
    )

    assert response.profile.recent_tactics == ["Discovery", "Collection"]
    assert response.profile.recent_techniques == ["T1046", "T1213"]
    evidences = evidence_repository.list_by_attacker("198.51.100.33")
    assert evidences[1].source_ref["opencanary_repo"] == "infra-deploy.git"
