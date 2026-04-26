"""FastAPI app for ingesting OpenCanary multi-protocol events."""

from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.contracts.models import OpenCanaryIngestRequest, OpenCanaryIngestResponse
from services.opencanary.domain import OpenCanaryService
from services.opencanary.runtime import get_runtime_service

app = FastAPI(title="opencanary-adapter", version="0.1.0")


def get_service() -> OpenCanaryService:
    """Return the default OpenCanary service used by the API."""
    return get_runtime_service()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Return a basic health check for local runners and deployment probes."""
    return {"status": "ok"}


@app.post("/v1/opencanary/events", response_model=OpenCanaryIngestResponse)
def ingest_opencanary_event(
    request: OpenCanaryIngestRequest,
    service: OpenCanaryService = Depends(get_service),
) -> OpenCanaryIngestResponse:
    """Ingest one parsed OpenCanary JSON event."""
    return service.ingest(request)

