"""Domain logic for the low-interaction public web honeypot.

This module captures HTTP requests, resolves a sticky binding for the source,
stores the raw observation, and forwards a normalized event into the profiler.
"""

from __future__ import annotations

import re
from uuid import uuid4

from libs.common.clock import utcnow
from libs.contracts.models import (
    EntrypointCaptureRequest,
    EntrypointCaptureResponse,
    EntrypointObservation,
    EvidenceIngestRequest,
    FalcoEvent,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.entrypoint.repository import EntrypointObservationRepository
from services.profiler.domain import ProfilerService


_SECRET_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}
# Redact common form/query-style secrets from the saved body preview. The
# entrypoint should collect attacker behavior, not accidentally persist secrets.
_SECRET_BODY_FIELD_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api_key|apikey|access_key)=([^&\s]+)"
)
_SCANNER_USER_AGENT_MARKERS = (
    "dirbuster",
    "feroxbuster",
    "ffuf",
    "gobuster",
    "masscan",
    "nikto",
    "nmap",
    "sqlmap",
    "wpscan",
)
_CREDENTIAL_PATH_MARKERS = (
    ".env",
    "backup",
    "password",
    "passwd",
    "secret",
    "token",
)
_CREDENTIAL_PATH_SUFFIXES = (
    ".bak",
    ".old",
    ".sql",
    ".zip",
    ".tar",
    ".tgz",
    ".gz",
    ".7z",
    ".rar",
)
_LOGIN_PATH_MARKERS = (
    "login",
    "signin",
    "wp-login.php",
)
_DISCOVERY_PATH_MARKERS = (
    ".git",
    ".svn",
    ".hg",
    ".ds_store",
    "/admin",
    "/api",
    "/phpmyadmin",
    "/status",
)
_DISCOVERY_PATH_SUFFIXES = (
    ".map",
)
_EXPLOIT_MARKERS = (
    "${jndi:",
    "jndi:ldap",
    "log4j",
    "struts",
    "spring.cloud.function.routing-expression",
    "../",
    "..%2f",
    "%2e%2e",
)


class EntrypointService:
    """Capture public HTTP probes and feed them into the profiling pipeline.

    Example:
        capture_http_request(GET /.env) -> observation + binding + profile update
    """

    def __init__(
        self,
        binding_service: BindingService,
        profiler_service: ProfilerService,
        observation_repository: EntrypointObservationRepository,
    ) -> None:
        self._binding_service = binding_service
        self._profiler_service = profiler_service
        self._observation_repository = observation_repository

    def capture_http_request(
        self,
        request: EntrypointCaptureRequest,
    ) -> EntrypointCaptureResponse:
        """Capture one HTTP request and update binding/profile state."""
        now = utcnow()
        # The binding service owns attacker session identity. Entrypoint only
        # asks for the current sticky binding for this source and protocol.
        binding = self._binding_service.resolve(
            ResolveBindingRequest(
                attacker_key=request.attacker_key,
                protocol=request.protocol,
            )
        )

        # Store only sanitized request material. Headers/body previews are still
        # useful for research, but raw credentials should never be persisted.
        safe_headers = _redact_headers(request.headers)
        safe_body_preview = _redact_body_preview(request.body_preview)
        output = _format_http_output(request)

        # Feed the HTTP probe into the same profiler path as other telemetry.
        # The entrypoint does not attach MITRE tags yet because a path probe such
        # as "/admin" or "/.env" is useful signal but not enough to justify a
        # specific ATT&CK technique on its own.
        ingest_response = self._profiler_service.ingest(
            EvidenceIngestRequest(
                attacker_key=request.attacker_key,
                binding_id=binding.binding_id,
                event=FalcoEvent(
                    ts=now,
                    falco_rule="HTTP honeypot request",
                    priority="INFO",
                    output=output,
                    tags=_http_profile_tags(request, safe_headers),
                    output_fields={
                        "http_method": request.method.upper(),
                        "http_path": request.path,
                        "http_query_string": request.query_string,
                        "http_user_agent": safe_headers.get("user-agent"),
                        "http_body_preview": safe_body_preview,
                    },
                ),
            )
        )

        # Observation is the research/debug record for this public-web probe.
        # The profiler_evidence_ids link it back to the normalized evidence
        # generated above.
        observation = EntrypointObservation(
            observation_id=str(uuid4()),
            ts=now,
            attacker_key=request.attacker_key,
            binding_id=binding.binding_id,
            method=request.method.upper(),
            path=request.path,
            query_string=request.query_string,
            headers=safe_headers,
            body_preview=safe_body_preview,
            body_truncated=request.body_truncated,
            user_agent=safe_headers.get("user-agent"),
            status_code=404,
            profiler_evidence_ids=[
                evidence.evidence_id for evidence in ingest_response.evidences
            ],
        )
        stored_observation = self._observation_repository.add(observation)
        return EntrypointCaptureResponse(
            observation=stored_observation,
            binding=binding,
            profile=ingest_response.profile,
        )


def _format_http_output(request: EntrypointCaptureRequest) -> str:
    """Build the compact human-readable message stored in profiler evidence."""
    target = request.path
    if request.query_string:
        target = f"{target}?{request.query_string}"
    return f"{request.method.upper()} {target} from {request.attacker_key}"


def _http_profile_tags(
    request: EntrypointCaptureRequest,
    safe_headers: dict[str, str],
) -> list[str]:
    """Map obvious public HTTP probes into coarse ATT&CK evidence tags."""
    path = request.path.lower()
    query_string = request.query_string.lower()
    body_preview = (request.body_preview or "").lower()
    user_agent = safe_headers.get("user-agent", "").lower()
    searchable = " ".join([path, query_string, body_preview, user_agent])

    if any(marker in searchable for marker in _EXPLOIT_MARKERS):
        return ["mitre_initial_access", "T1190"]
    if _looks_like_login_attempt(path, request.method, body_preview):
        return ["mitre_credential_access", "T1110"]
    if _looks_like_credential_discovery(path, query_string):
        return ["mitre_credential_access", "T1552.001"]
    if _looks_like_web_discovery(path, user_agent):
        return ["mitre_discovery", "T1046"]
    return []


def _looks_like_login_attempt(path: str, method: str, body_preview: str) -> bool:
    if any(marker in path for marker in _LOGIN_PATH_MARKERS):
        return True
    return method.upper() == "POST" and any(
        marker in body_preview
        for marker in ("password", "passwd", "pwd=", "username", "login")
    )


def _looks_like_credential_discovery(path: str, query_string: str) -> bool:
    target = f"{path}?{query_string}" if query_string else path
    if any(marker in target for marker in _CREDENTIAL_PATH_MARKERS):
        return True
    return target.endswith(_CREDENTIAL_PATH_SUFFIXES)


def _looks_like_web_discovery(path: str, user_agent: str) -> bool:
    if any(marker in user_agent for marker in _SCANNER_USER_AGENT_MARKERS):
        return True
    if any(marker in path for marker in _DISCOVERY_PATH_MARKERS):
        return True
    return path.endswith(_DISCOVERY_PATH_SUFFIXES)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Normalize header names and hide values that commonly carry secrets."""
    safe_headers: dict[str, str] = {}
    for name, value in headers.items():
        normalized_name = name.lower()
        safe_headers[normalized_name] = (
            "[redacted]" if normalized_name in _SECRET_HEADER_NAMES else value
        )
    return safe_headers


def _redact_body_preview(body_preview: str | None) -> str | None:
    """Hide obvious key=value secrets from the stored request body preview."""
    if body_preview is None:
        return None
    return _SECRET_BODY_FIELD_RE.sub(r"\1=[redacted]", body_preview)
