from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException

from libs.contracts.models import (
    EvidenceIngestRequest,
    EvidenceIngestResponse,
    ProfileSnapshot,
)
from services.profiler.domain import ProfileNotFoundError, ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository

app = FastAPI(title="profiler", version="0.1.0")

# Default in-memory wiring keeps the service runnable locally.
_evidence_repository = InMemoryEvidenceRepository()
_profile_repository = InMemoryProfileRepository()
_service = ProfilerService(_evidence_repository, _profile_repository)


def get_service() -> ProfilerService:
    # Tests replace this dependency with an isolated service.
    return _service


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
