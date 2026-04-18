from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from libs.common.config import RuntimeConfig
from libs.contracts.models import EvidenceIngestRequest, FalcoEvent
from services.profiler.domain import ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


pytestmark = pytest.mark.unit


def test_ingest_maps_falco_event_into_attack_profile() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.10",
            binding_id="binding-1",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="Read sensitive file",
                priority="WARNING",
                output="Sensitive file read /etc/shadow",
                tags=["filesystem", "mitre_credential_access", "T1003"],
                output_fields={"proc_cmdline": "cat /etc/shadow"},
            ),
        )
    )

    assert response.evidences[0].tech_id == "T1003"
    assert response.evidences[0].group == "Credential Access"
    assert response.profile.conf_by_tactic["Credential Access"] > 0.0
    assert response.profile.recent_tactics == ["Credential Access"]
    assert response.profile.recent_techniques == ["T1003"]


def test_profile_recent_sequence_respects_time_window() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
        config=RuntimeConfig(chain_window_seconds=300),
    )
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.20",
            binding_id="binding-2",
            event=FalcoEvent(
                ts=start,
                falco_rule="MySQL probe",
                priority="INFO",
                output="mysql service probe",
                tags=[],
                output_fields={},
            ),
        )
    )
    latest = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.20",
            binding_id="binding-2",
            event=FalcoEvent(
                ts=start + timedelta(seconds=600),
                falco_rule="Read sensitive file",
                priority="WARNING",
                output="Sensitive file read /etc/shadow",
                tags=["mitre_credential_access", "T1003"],
                output_fields={},
            ),
        )
    )

    assert latest.profile.recent_tactics == ["Credential Access"]
    assert "Discovery" not in latest.profile.recent_tactics


def test_ingest_extracts_subtechnique_ids_from_realistic_falco_tags() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.30",
            binding_id="binding-3",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="Read sensitive file trusted_after",
                priority="WARNING",
                output="Possible credential leak in container",
                tags=[
                    "maturity_stable",
                    "host",
                    "container",
                    "process",
                    "filesystem",
                    "mitre_credential_access",
                    "T1552.001",
                ],
                output_fields={},
            ),
        )
    )

    assert response.evidences[0].tech_id == "T1552.001"
    assert response.evidences[0].group == "Credential Access"


def test_ingest_uses_catalog_default_when_only_tactic_tag_is_present() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.40",
            binding_id="binding-4",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="Launch Privileged Container",
                priority="CRITICAL",
                output="Privileged container started",
                tags=["mitre_privilege_escalation"],
                output_fields={},
            ),
        )
    )

    assert response.evidences[0].tech_id is None
    assert response.evidences[0].group == "Privilege Escalation"


def test_ingest_keeps_untagged_events_unclassified() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.41",
            binding_id="binding-5",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="Unexpected process launch",
                priority="WARNING",
                output="Command execution observed",
                tags=[],
                output_fields={"proc_cmdline": "bash -c whoami"},
            ),
        )
    )

    assert response.evidences[0].tech_id is None
    assert response.evidences[0].group is None
    assert response.profile.conf_by_tactic == {}
    assert response.profile.recent_tactics == []
