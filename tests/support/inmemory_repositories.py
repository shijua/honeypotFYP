"""In-memory test doubles for repository protocols.

Runtime services use file-backed adapters by default. These lightweight stores
stay under `tests/support` so production modules only expose real adapters plus
their storage protocols.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Generic, TypeVar

from libs.contracts.models import (
    AssetDefinition,
    AssetRuntimeRecord,
    BindingRecord,
    CowrieObservation,
    EntrypointObservation,
    GatewayBindingState,
    HighInteractionObservation,
    OpenCanaryObservation,
    ProfileSnapshot,
    TechniqueEvidence,
)


ObservationT = TypeVar("ObservationT")


class InMemoryBindingRepository:
    """In-memory binding store for unit/component tests."""

    def __init__(self) -> None:
        self._by_binding: dict[str, BindingRecord] = {}
        self._by_attacker: dict[str, str] = {}

    def get_by_attacker(self, attacker_key: str) -> BindingRecord | None:
        binding_id = self._by_attacker.get(attacker_key)
        if binding_id is None:
            return None
        return self._by_binding.get(binding_id)

    def get_by_binding(self, binding_id: str) -> BindingRecord | None:
        return self._by_binding.get(binding_id)

    def upsert(self, record: BindingRecord) -> BindingRecord:
        self._by_binding[record.binding_id] = record
        self._by_attacker[record.attacker_key] = record.binding_id
        return record

    def list_all(self) -> Iterable[BindingRecord]:
        return tuple(self._by_binding.values())


class InMemoryGatewayRouteRepository:
    """In-memory gateway route store for tests."""

    def __init__(self) -> None:
        self._by_binding: dict[str, GatewayBindingState] = {}

    def get(self, binding_id: str) -> GatewayBindingState | None:
        return self._by_binding.get(binding_id)

    def get_by_attacker(self, attacker_key: str) -> GatewayBindingState | None:
        for state in self._by_binding.values():
            if state.attacker_key == attacker_key:
                return state
        return None

    def upsert(self, state: GatewayBindingState) -> GatewayBindingState:
        self._by_binding[state.binding_id] = state
        return state

    def list_all(self) -> Iterable[GatewayBindingState]:
        return tuple(self._by_binding.values())


class _InMemoryObservationRepository(Generic[ObservationT]):
    """Shared append-only observation store for repository unit tests."""

    def __init__(self) -> None:
        self._observations: list[ObservationT] = []

    def add(self, observation: ObservationT) -> ObservationT:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[ObservationT]:
        return tuple(self._observations[-limit:])


class InMemoryEntrypointObservationRepository(
    _InMemoryObservationRepository[EntrypointObservation]
):
    """In-memory public entrypoint observation store for tests."""


class InMemoryCowrieObservationRepository(
    _InMemoryObservationRepository[CowrieObservation]
):
    """In-memory Cowrie observation store for tests."""


class InMemoryOpenCanaryObservationRepository(
    _InMemoryObservationRepository[OpenCanaryObservation]
):
    """In-memory OpenCanary observation store for tests."""


class InMemoryHighInteractionObservationRepository(
    _InMemoryObservationRepository[HighInteractionObservation]
):
    """In-memory high-interaction observation store for tests."""


class InMemoryEvidenceRepository:
    """In-memory profiler evidence store for tests."""

    def __init__(self) -> None:
        self._by_attacker: dict[str, list[TechniqueEvidence]] = {}

    def add_many(
        self,
        attacker_key: str,
        evidences: list[TechniqueEvidence],
    ) -> list[TechniqueEvidence]:
        bucket = self._by_attacker.setdefault(attacker_key, [])
        bucket.extend(evidences)
        return evidences

    def list_by_attacker(self, attacker_key: str) -> Iterable[TechniqueEvidence]:
        return tuple(self._by_attacker.get(attacker_key, ()))


class InMemoryProfileRepository:
    """In-memory profile snapshot store for tests."""

    def __init__(self) -> None:
        self._by_attacker: dict[str, ProfileSnapshot] = {}

    def get(self, attacker_key: str) -> ProfileSnapshot | None:
        return self._by_attacker.get(attacker_key)

    def upsert(self, snapshot: ProfileSnapshot) -> ProfileSnapshot:
        self._by_attacker[snapshot.attacker_key] = snapshot
        return snapshot


class InMemoryAssetRepository:
    """Small static asset catalog for controller/orchestrator tests."""

    def __init__(self, assets: list[AssetDefinition] | None = None) -> None:
        self._assets = assets or [
            AssetDefinition(
                asset_id="internal-portal",
                asset_name="Internal Portal",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Discovery"],
                dependencies=[],
                default_settings={
                    "selection_profile": {
                        "asset_group": "portal",
                        "covered_techniques": ["T1046", "T1083"],
                        "telemetry_value": 0.6,
                        "tactic_difficulties": {"Discovery": 1},
                        "reveal_outputs": ["service directory"],
                        "selection_notes": "Bootstrap internal discovery surface.",
                    }
                },
            ),
            AssetDefinition(
                asset_id="finance-share",
                asset_name="Finance File Share",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Collection"],
                dependencies=["internal-portal"],
                default_settings={
                    "unlock_signals": {
                        "any_http_paths": ["/backup/db_backup_2024.sql.bak"],
                        "any_http_indicators": ["path:.bak"],
                    },
                    "selection_profile": {
                        "asset_group": "data-share",
                        "covered_techniques": ["T1005", "T1552.001"],
                        "telemetry_value": 0.85,
                        "tactic_difficulties": {"Credential Access": 2, "Collection": 2},
                        "reveal_outputs": ["finance backup files"],
                        "selection_notes": "Data and credential breadcrumb follow-up.",
                    },
                },
            ),
            AssetDefinition(
                asset_id="git-internal",
                asset_name="Internal Git",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Discovery"],
                dependencies=["internal-portal"],
                default_settings={
                    "unlock_signals": {
                        "any_http_paths": ["/.env.old", "/assets/app.js.map"],
                        "any_http_indicators": ["combined:.env", "path:.map"],
                    },
                    "selection_profile": {
                        "asset_group": "developer",
                        "covered_techniques": ["T1213", "T1552.001", "T1083"],
                        "telemetry_value": 0.9,
                        "tactic_difficulties": {"Credential Access": 3, "Discovery": 2},
                        "reveal_outputs": ["repository names"],
                        "selection_notes": "Developer artifact follow-up.",
                    },
                },
            ),
            AssetDefinition(
                asset_id="ops-db",
                asset_name="Operations Database",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Collection"],
                dependencies=["git-internal"],
                default_settings={
                    "selection_profile": {
                        "asset_group": "database",
                        "covered_techniques": ["T1005", "T1110"],
                        "telemetry_value": 0.85,
                        "tactic_difficulties": {"Credential Access": 3, "Collection": 4},
                        "reveal_outputs": ["database login prompt"],
                        "selection_notes": "Database credential follow-up.",
                    }
                },
            ),
            AssetDefinition(
                asset_id="admin-jumpbox",
                asset_name="Admin Jumpbox",
                exposure_type="internal",
                interaction_level="high",
                covers_tactics=["Lateral Movement", "Privilege Escalation"],
                dependencies=["git-internal"],
                default_settings={
                    "selection_profile": {
                        "asset_group": "admin-access",
                        "covered_techniques": ["T1021", "T1059"],
                        "telemetry_value": 0.9,
                        "tactic_difficulties": {"Lateral Movement": 4, "Privilege Escalation": 5},
                        "reveal_outputs": ["interactive command telemetry"],
                        "selection_notes": "High-interaction path.",
                    }
                },
            ),
        ]

    def list_all(self) -> Iterable[AssetDefinition]:
        return tuple(self._assets)


class InMemoryTechniquePriorRepository:
    """Small test repository for deterministic technique recommendations."""

    def __init__(
        self,
        recommendations: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self._recommendations = recommendations or {}

    @property
    def degraded_reason(self) -> str | None:
        return None

    def recommend(
        self,
        observed_techniques: set[str],
        *,
        top_k: int,
        support_threshold: float,
    ) -> dict[str, float]:
        scores: dict[str, float] = {}
        for technique in observed_techniques:
            for candidate, score in self._recommendations.get(technique, {}).items():
                if candidate in observed_techniques:
                    continue
                scores[candidate] = max(scores.get(candidate, 0.0), float(score))
        return dict(
            sorted(
                {
                    technique: score
                    for technique, score in scores.items()
                    if score >= support_threshold
                }.items(),
                key=lambda item: (-item[1], item[0]),
            )[:top_k]
        )


class InMemoryTemplateRuntimeRepository:
    """In-memory asset runtime record store for orchestrator tests."""

    def __init__(self) -> None:
        self._records: dict[str, AssetRuntimeRecord] = {}

    def upsert(self, record: AssetRuntimeRecord) -> AssetRuntimeRecord:
        self._records[record.runtime_id] = record
        return record

    def list_by_binding(self, binding_id: str) -> Iterable[AssetRuntimeRecord]:
        return tuple(
            record
            for record in self._records.values()
            if record.binding_id == binding_id
        )
