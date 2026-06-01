"""Domain logic for HTTP observation surfaces.

This module captures public website requests and already-unlocked internal HTTP
asset requests, resolves a sticky binding for the source, stores a redacted
observation, and sends suspicious HTTP probes into the profiler.
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
    ProfileSnapshot,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.entrypoint.repository import EntrypointObservationRepository
from services.entrypoint.rule_matcher import (
    PublicHttpRuleMatcher,
    PublicHttpRuleMatch,
)
from services.entrypoint.sigma_mapping import FilePublicHttpSigmaRuleMatcher
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


class EntrypointService:
    """Capture public HTTP probes and profile suspicious public-web behavior.

    Example:
        capture_http_request(GET /.env) -> observation + binding + profile update
    """

    def __init__(
        self,
        binding_service: BindingService,
        observation_repository: EntrypointObservationRepository,
        profiler_service: ProfilerService | None = None,
        public_http_rule_matcher: PublicHttpRuleMatcher | None = None,
    ) -> None:
        self._binding_service = binding_service
        self._observation_repository = observation_repository
        self._profiler_service = profiler_service
        self._public_http_rule_matcher = (
            public_http_rule_matcher or FilePublicHttpSigmaRuleMatcher()
        )

    def capture_http_request(
        self,
        request: EntrypointCaptureRequest,
    ) -> EntrypointCaptureResponse:
        """Capture one HTTP request and update binding/observation state."""
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

        # Only suspicious public HTTP requests become profiler evidence. Normal
        # public-page visits are retained as benign-surface context.
        rule_matches = self._public_http_rule_matcher.matches_for(
            method=request.method,
            path=request.path,
            query_string=request.query_string,
            body_preview=safe_body_preview,
            user_agent=safe_headers.get("user-agent"),
            surface=request.surface,
            asset_id=request.asset_id,
        )
        tags = _tags_from_rule_matches(rule_matches)
        indicators = _indicators_from_rule_matches(rule_matches)
        matched_rules = [match.rule_name for match in rule_matches]
        evidence_labels = [
            match.evidence_label
            for match in rule_matches
            if match.evidence_label is not None
        ]
        profile = ProfileSnapshot(attacker_key=request.attacker_key)
        profiler_evidence_ids: list[str] = []
        if rule_matches and self._profiler_service is not None:
            ingest_response = self._profiler_service.ingest(
                EvidenceIngestRequest(
                    attacker_key=request.attacker_key,
                    binding_id=binding.binding_id,
                    event=FalcoEvent(
                        ts=now,
                        falco_rule=_falco_rule_for_surface(request.surface),
                        priority="low",
                        output=_format_http_output(request, indicators),
                        tags=tags,
                        output_fields={
                            "source": _source_for_surface(request.surface),
                            "http_surface": request.surface,
                            "asset_id": request.asset_id,
                            "http_method": request.method.upper(),
                            "http_path": request.path,
                            "http_query_string": request.query_string,
                            "http_user_agent": safe_headers.get("user-agent"),
                            "http_body_preview": safe_body_preview,
                            "http_rule_names": matched_rules,
                            "http_indicators": indicators,
                            "http_evidence_labels": evidence_labels,
                        },
                    ),
                )
            )
            profile = ingest_response.profile
            profiler_evidence_ids = [
                evidence.evidence_id for evidence in ingest_response.evidences
            ]

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
            matched_rules=matched_rules,
            tags=tags,
            indicators=indicators,
            profiler_evidence_ids=profiler_evidence_ids,
            surface=request.surface,
            asset_id=request.asset_id,
        )
        stored_observation = self._observation_repository.add(observation)
        return EntrypointCaptureResponse(
            observation=stored_observation,
            binding=binding,
            profile=profile,
        )


def _format_http_output(
    request: EntrypointCaptureRequest,
    indicators: list[str] | None = None,
) -> str:
    """Build the compact human-readable message stored in profiler evidence."""
    target = request.path
    if request.query_string:
        target = f"{target}?{request.query_string}"
    surface = request.surface
    asset = f" asset={request.asset_id}" if request.asset_id else ""
    output = f"{surface} HTTP {request.method.upper()} {target}{asset} from {request.attacker_key}"
    if indicators:
        output = f"{output}; indicators={', '.join(indicators)}"
    return output


def _source_for_surface(surface: str) -> str:
    """Return the profiler source label for public vs internal HTTP."""
    return "internal_http" if surface == "internal" else "public_http"


def _falco_rule_for_surface(surface: str) -> str:
    """Return a stable event title for profiler evidence."""
    if surface == "internal":
        return "Internal HTTP asset request"
    return "HTTP honeypot request"


def _tags_from_rule_matches(rule_matches: list[PublicHttpRuleMatch]) -> list[str]:
    tags: list[str] = []
    for match in rule_matches:
        for tag in match.tags:
            if tag not in tags:
                tags.append(tag)
    return tags


def _indicators_from_rule_matches(rule_matches: list[PublicHttpRuleMatch]) -> list[str]:
    indicators: list[str] = []
    for match in rule_matches:
        for indicator in match.indicators:
            if indicator not in indicators:
                indicators.append(indicator)
    return indicators


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
