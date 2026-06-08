"""FastAPI app for Dionaea, Glutton, and Wordpot capture telemetry."""

from __future__ import annotations

from fastapi import Depends, FastAPI

from libs.contracts.models import HighInteractionIngestRequest, HighInteractionIngestResponse
from services.high_interaction.domain import HighInteractionService
from services.high_interaction.runtime import get_runtime_service

app = FastAPI(title="high-interaction-adapter", version="0.1.0")


def get_service() -> HighInteractionService:
    """Return the default high-interaction service used by the API."""
    return get_runtime_service()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Return a basic liveness check for compose probes."""
    return {"status": "ok"}


@app.post("/v1/high-interaction/events", response_model=HighInteractionIngestResponse)
def ingest_high_interaction_event(
    request: HighInteractionIngestRequest,
    service: HighInteractionService = Depends(get_service),
) -> HighInteractionIngestResponse:
    """Ingest one normalized high-interaction event."""
    return service.ingest(request)
