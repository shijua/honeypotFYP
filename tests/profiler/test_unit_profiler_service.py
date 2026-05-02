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


def test_profile_rebuild_accepts_mixed_naive_and_aware_datetimes() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.21",
            binding_id="binding-2",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, 12, 0, 0),
                falco_rule="OpenCanary redis event",
                priority="INFO",
                output="redis probe",
                tags=["mitre_discovery", "T1046"],
                output_fields={},
            ),
        )
    )
    latest = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.21",
            binding_id="binding-2",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc),
                falco_rule="HTTP honeypot request",
                priority="INFO",
                output="GET /.env",
                tags=[],
                output_fields={},
            ),
        )
    )

    assert latest.profile.updated_at.tzinfo is not None
    assert latest.profile.recent_techniques == ["T1046"]


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


def test_ingest_preserves_public_http_source_ref_fields() -> None:
    # Public HTTP evidence has two jobs: it contributes ATT&CK context and it
    # carries exact path/rule breadcrumbs for later controller decisions.
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.50",
            binding_id="binding-6",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="HTTP honeypot request",
                priority="WARNING",
                output="HTTP GET /api/search?q=1 union select 1 matched public_http_injection_probe",
                tags=["mitre_discovery", "T1046"],
                output_fields={
                    "source": "public_http",
                    "http_method": "GET",
                    "http_path": "/api/search",
                    "http_query_string": "q=1 union select 1",
                    "http_user_agent": "sqlmap/1.8",
                    "http_rule_names": ["public_http_injection_probe"],
                    "http_indicators": ["user_agent:sqlmap", "combined:union%20select"],
                    "http_evidence_labels": ["public-http injection or exploit probe"],
                },
            ),
        )
    )

    source_ref = response.evidences[0].source_ref
    assert source_ref["source"] == "public_http"
    assert source_ref["http_path"] == "/api/search"
    assert source_ref["http_query_string"] == "q=1 union select 1"
    assert source_ref["http_user_agent"] == "sqlmap/1.8"
    assert source_ref["http_rule_names"] == ["public_http_injection_probe"]
    assert source_ref["http_indicators"] == ["user_agent:sqlmap", "combined:union%20select"]
    assert source_ref["http_evidence_labels"] == ["public-http injection or exploit probe"]
    assert response.profile.recent_public_http_paths == ["/api/search"]
    assert response.profile.recent_public_http_rules == ["public_http_injection_probe"]
    assert response.profile.recent_public_http_indicators == [
        "user_agent:sqlmap",
        "combined:union%20select",
    ]


def test_ingest_preserves_internal_http_source_ref_fields() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.52",
            binding_id="binding-8",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="Internal HTTP asset request",
                priority="INFO",
                output="internal HTTP GET /downloads/agent-update.bin asset=malware-sink",
                tags=["mitre_collection", "T1005"],
                output_fields={
                    "source": "internal_http",
                    "http_surface": "internal",
                    "asset_id": "malware-sink",
                    "http_method": "GET",
                    "http_path": "/downloads/agent-update.bin",
                    "http_rule_names": ["internal_http_artifact_access"],
                    "http_indicators": ["path:.bin"],
                },
            ),
        )
    )

    source_ref = response.evidences[0].source_ref
    assert source_ref["source"] == "internal_http"
    assert source_ref["http_surface"] == "internal"
    assert source_ref["asset_id"] == "malware-sink"
    assert response.profile.recent_internal_http_paths == [
        "/downloads/agent-update.bin"
    ]
    assert response.profile.recent_internal_http_rules == [
        "internal_http_artifact_access"
    ]
    assert response.profile.recent_internal_http_indicators == ["path:.bin"]


def test_ingest_maps_multi_tactic_public_http_tags_per_technique() -> None:
    service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )

    response = service.ingest(
        EvidenceIngestRequest(
            attacker_key="198.51.100.51",
            binding_id="binding-7",
            event=FalcoEvent(
                ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
                falco_rule="HTTP honeypot request",
                priority="INFO",
                output="GET /api/search?q=1%20union%20select%201",
                    tags=[
                        "mitre_initial_access",
                        "T1566",
                        "mitre_discovery",
                        "T1046",
                ],
                output_fields={"source": "public_http"},
            ),
        )
    )

    evidence_by_technique = {
        evidence.tech_id: evidence.group for evidence in response.evidences
    }

    assert evidence_by_technique == {
        "T1566": "Initial Access",
        "T1046": "Discovery",
    }
    assert response.profile.recent_tactics == ["Initial Access", "Discovery"]
