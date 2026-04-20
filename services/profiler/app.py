"""FastAPI entrypoints for attacker profiling.

The profiler API ingests Falco events and exposes the latest per-attacker
profile snapshot used by the controller.
"""

from __future__ import annotations

from functools import lru_cache

from fastapi import Depends, FastAPI, HTTPException

from libs.common.config import RuntimeConfig
from libs.contracts.models import (
    EvidenceIngestRequest,
    EvidenceIngestResponse,
    ProfileSnapshot,
)
from services.profiler.attack_catalog import MitreAttackCatalog
from services.profiler.domain import ProfileNotFoundError, ProfilerService
from services.profiler.repository import FileEvidenceRepository, FileProfileRepository

app = FastAPI(title="profiler", version="0.1.0")


@lru_cache(maxsize=1)
def _build_service() -> ProfilerService:
    """Build the default profiler service with file-backed local storage."""
    # Default local wiring persists profiler state and ATT&CK data on disk.
    config = RuntimeConfig()
    evidence_repository = FileEvidenceRepository(f"{config.state_dir}/evidence.json")
    profile_repository = FileProfileRepository(f"{config.state_dir}/profiles.json")
    attack_catalog = MitreAttackCatalog(config.mitre_attack_stix_path)
    return ProfilerService(
        evidence_repository,
        profile_repository,
        attack_catalog,
        config=config,
    )


def get_service() -> ProfilerService:
    """Return the default profiler service used by the API."""
    # Tests replace this dependency with an isolated service.
    return _build_service()


@app.post("/v1/evidence/ingest", response_model=EvidenceIngestResponse)
def ingest_evidence(
    request: EvidenceIngestRequest,
    service: ProfilerService = Depends(get_service),
) -> EvidenceIngestResponse:
    """Translate one Falco event into ATT&CK evidence and refresh the profile."""
    return service.ingest(request)


@app.get("/v1/profiles/{attacker_key}", response_model=ProfileSnapshot)
def get_profile(
    attacker_key: str,
    service: ProfilerService = Depends(get_service),
) -> ProfileSnapshot:
    """Return the current attacker profile snapshot."""
    try:
        return service.get_profile(attacker_key)
    except ProfileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="profile not found") from exc
