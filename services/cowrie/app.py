"""FastAPI app for ingesting Cowrie SSH honeypot events.

A Kubernetes log collector or sidecar can POST parsed Cowrie JSON records to
this API so SSH interaction data flows into the profiler.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.contracts.models import CowrieIngestRequest, CowrieIngestResponse
from services.cowrie.domain import CowrieService
from services.cowrie.runtime import get_runtime_service

app = FastAPI(title="cowrie-adapter", version="0.1.0")


def get_service() -> CowrieService:
    """Return the default Cowrie service used by the API."""
    return get_runtime_service()


@app.post("/v1/cowrie/events", response_model=CowrieIngestResponse)
def ingest_cowrie_event(
    request: CowrieIngestRequest,
    service: CowrieService = Depends(get_service),
) -> CowrieIngestResponse:
    """Ingest one parsed Cowrie JSON event."""
    return service.ingest(request)
