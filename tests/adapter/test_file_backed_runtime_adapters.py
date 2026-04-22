from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from libs.contracts.models import (
    BindingRecord,
    BindingStatus,
    CowrieObservation,
    EntrypointObservation,
    GatewayBindingState,
    AssetRuntimeRecord,
    ProfileSnapshot,
    TechniqueEvidence,
)
from services.binding_service.repository import FileBindingRepository
from services.controller.repository import FileAssetRepository
from services.cowrie.repository import FileCowrieObservationRepository
from services.entrypoint.repository import FileEntrypointObservationRepository
from services.gateway.repository import FileGatewayRouteRepository
from services.orchestrator.template_runtime import FileTemplateRuntimeRepository
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
                    "description": "Fake internal web app",
                    "template_family": "web-honeypot",
                    "protocols": ["http"],
                    "ports": [80],
                    "source_refs": ["tpotce:snare"],
                    "covers_tactics": ["Discovery"],
                    "dependencies": [],
                }
            ]
        ),
        encoding="utf-8",
    )

    repository = FileAssetRepository(path)

    asset = tuple(repository.list_all())[0]
    assert asset.asset_id == "internal-portal"
    assert asset.template_family == "web-honeypot"
    assert asset.protocols == ["http"]
    assert asset.ports == [80]
    assert asset.source_refs == ["tpotce:snare"]


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


def test_file_template_runtime_repository_persists_asset_runtime(tmp_path) -> None:
    repository = FileTemplateRuntimeRepository(tmp_path / "asset_runtime.json")
    record = AssetRuntimeRecord(
        runtime_id="runtime-1",
        binding_id="binding-asset",
        asset_id="admin-jumpbox",
        asset_name="Admin Jumpbox",
        template_family="ssh-honeypot",
        protocols=["ssh"],
        ports=[22],
        settings={"hostname": "admin-jumpbox-01"},
        source_refs=["tpotce:cowrie"],
    )

    repository.upsert(record)

    reloaded = FileTemplateRuntimeRepository(tmp_path / "asset_runtime.json")
    records = tuple(reloaded.list_by_binding("binding-asset"))
    assert len(records) == 1
    assert records[0].settings["hostname"] == "admin-jumpbox-01"


def test_file_entrypoint_repository_persists_observations(tmp_path) -> None:
    repository = FileEntrypointObservationRepository(tmp_path / "entrypoint.json")
    observation = EntrypointObservation(
        observation_id="obs-1",
        ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        attacker_key="198.51.100.93",
        binding_id="binding-4",
        method="GET",
        path="/.env",
        status_code=404,
        profiler_evidence_ids=["e-1"],
    )

    repository.add(observation)

    reloaded = FileEntrypointObservationRepository(tmp_path / "entrypoint.json")
    assert tuple(reloaded.list_recent())[0].observation_id == "obs-1"


def test_file_cowrie_repository_persists_observations(tmp_path) -> None:
    repository = FileCowrieObservationRepository(tmp_path / "cowrie.json")
    observation = CowrieObservation(
        observation_id="obs-2",
        ts=datetime(2026, 1, 1, tzinfo=timezone.utc),
        attacker_key="198.51.100.94",
        binding_id="binding-5",
        eventid="cowrie.command.input",
        command="uname -a",
        profiler_evidence_ids=["e-2"],
    )

    repository.add(observation)

    reloaded = FileCowrieObservationRepository(tmp_path / "cowrie.json")
    assert tuple(reloaded.list_recent())[0].observation_id == "obs-2"


def test_file_repositories_create_default_json_files(tmp_path) -> None:
    binding_path = tmp_path / "runtime" / "bindings.json"
    cowrie_path = tmp_path / "runtime" / "cowrie_observations.json"
    evidence_path = tmp_path / "runtime" / "evidence.json"
    profile_path = tmp_path / "runtime" / "profiles.json"

    FileBindingRepository(binding_path)
    FileCowrieObservationRepository(cowrie_path)
    FileEvidenceRepository(evidence_path)
    FileProfileRepository(profile_path)

    assert json.loads(binding_path.read_text(encoding="utf-8")) == {"records": []}
    assert json.loads(cowrie_path.read_text(encoding="utf-8")) == {
        "observations": []
    }
    assert json.loads(evidence_path.read_text(encoding="utf-8")) == {"records": {}}
    assert json.loads(profile_path.read_text(encoding="utf-8")) == {"profiles": {}}
