from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from libs.contracts.models import (
    BindingRecord,
    BindingStatus,
    GatewayBindingState,
    ProfileSnapshot,
    TechniqueEvidence,
)
from services.binding_service.repository import FileBindingRepository
from services.controller.repository import FileAssetRepository
from services.gateway.repository import FileGatewayRouteRepository
from services.profiler.repository import FileEvidenceRepository, FileProfileRepository


pytestmark = pytest.mark.adapter


def test_file_binding_repository_persists_records(tmp_path) -> None:
    repository = FileBindingRepository(tmp_path / "bindings.json")
    record = BindingRecord(
        binding_id="binding-1",
        attacker_key="198.51.100.90",
        backend_instance_id="ns-binding",
        status=BindingStatus.active,
        first_seen_ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        last_seen_ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ttl_expires_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )

    repository.upsert(record)

    reloaded = FileBindingRepository(tmp_path / "bindings.json")
    assert reloaded.get_by_binding("binding-1") is not None


def test_file_profiler_repositories_persist_state(tmp_path) -> None:
    evidence_repository = FileEvidenceRepository(tmp_path / "evidence.json")
    profile_repository = FileProfileRepository(tmp_path / "profiles.json")
    evidence = TechniqueEvidence(
        evidence_id="e-1",
        ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        attacker_key="198.51.100.91",
        binding_id="binding-2",
        tech_id="T1003",
        group="Credential Access",
        weight=2.5,
        success=True,
        reason="shadow read",
    )
    profile = ProfileSnapshot(
        attacker_key="198.51.100.91",
        conf_by_tactic={"Credential Access": 0.8},
    )

    evidence_repository.add_many("198.51.100.91", [evidence])
    profile_repository.upsert(profile)

    reloaded_evidence = FileEvidenceRepository(tmp_path / "evidence.json")
    reloaded_profile = FileProfileRepository(tmp_path / "profiles.json")
    assert len(tuple(reloaded_evidence.list_by_attacker("198.51.100.91"))) == 1
    assert reloaded_profile.get("198.51.100.91") is not None


def test_file_asset_repository_reads_external_catalog(tmp_path) -> None:
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            [
                {
                    "asset_id": "internal-portal",
                    "asset_name": "Internal Portal",
                    "exposure_type": "internal",
                    "interaction_level": "medium",
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                }
            ]
        ),
        encoding="utf-8",
    )

    repository = FileAssetRepository(path)

    assert tuple(repository.list_all())[0].asset_id == "internal-portal"


def test_file_gateway_repository_persists_route_state(tmp_path) -> None:
    repository = FileGatewayRouteRepository(tmp_path / "gateway.json")
    state = GatewayBindingState(
        binding_id="binding-3",
        attacker_key="198.51.100.92",
        backend_instance_id="ns-binding",
        status=BindingStatus.active,
        exposed_assets=["finance-share"],
        route_updates=["binding binding-3 exposes finance-share"],
    )

    repository.upsert(state)

    reloaded = FileGatewayRouteRepository(tmp_path / "gateway.json")
    assert reloaded.get("binding-3") is not None
