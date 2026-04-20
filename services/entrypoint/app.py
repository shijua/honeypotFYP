"""FastAPI app for the low-interaction public web honeypot.

All non-health HTTP paths are treated as honeypot probes: the request is
captured, persisted, sent to the profiler, and answered with a plain 404.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

from libs.common.config import RuntimeConfig
from libs.contracts.models import EntrypointCaptureRequest
from services.entrypoint.domain import EntrypointService
from services.entrypoint.runtime import get_runtime_service

app = FastAPI(title="entrypoint", version="0.1.0")
_config = RuntimeConfig()


def get_service() -> EntrypointService:
    """Return the default entrypoint service used by the API."""
    return get_runtime_service()


@app.get("/healthz")
def healthz() -> dict[str, str]:
    """Return a basic health check for deployment probes."""
    return {"status": "ok"}


@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def capture_probe(
    path: str,
    request: Request,
    service: EntrypointService = Depends(get_service),
) -> Response:
    """Capture arbitrary public HTTP traffic as low-interaction honeypot data."""
    raw_body = await request.body()
    body_preview = _body_preview(raw_body)
    service.capture_http_request(
        EntrypointCaptureRequest(
            attacker_key=_attacker_key(request),
            method=request.method,
            path=f"/{path}",
            query_string=request.url.query,
            headers=dict(request.headers),
            body_preview=body_preview,
            body_truncated=len(raw_body) > _config.entrypoint_body_preview_bytes,
        )
    )
    if request.method == "HEAD":
        return Response(status_code=404)
    return PlainTextResponse("Not Found\n", status_code=404)


def _attacker_key(request: Request) -> str:
    # Use the ASGI client host to avoid trusting spoofable forwarding headers.
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _body_preview(raw_body: bytes) -> str | None:
    if not raw_body:
        return None
    preview = raw_body[: _config.entrypoint_body_preview_bytes]
    return preview.decode("utf-8", errors="replace")
