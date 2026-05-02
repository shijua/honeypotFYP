"""In-memory test doubles for repository protocols.

Runtime services use file-backed adapters by default. These lightweight stores
stay under `tests/support` so production modules only expose real adapters plus
their storage protocols.
"""

from __future__ import annotations

from collections.abc import Iterable

from libs.contracts.models import (
    AssetDefinition,
    AssetRuntimeRecord,
    BindingRecord,
    CowrieObservation,
    EntrypointObservation,
    GatewayBindingState,
    OpenCanaryObservation,
    ProfileSnapshot,
    TechniqueEvidence,
)


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


class InMemoryEntrypointObservationRepository:
    """In-memory public entrypoint observation store for tests."""

    def __init__(self) -> None:
        self._observations: list[EntrypointObservation] = []

    def add(self, observation: EntrypointObservation) -> EntrypointObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[EntrypointObservation]:
        return tuple(self._observations[-limit:])


class InMemoryCowrieObservationRepository:
    """In-memory Cowrie observation store for tests."""

    def __init__(self) -> None:
        self._observations: list[CowrieObservation] = []

    def add(self, observation: CowrieObservation) -> CowrieObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[CowrieObservation]:
        return tuple(self._observations[-limit:])


class InMemoryOpenCanaryObservationRepository:
    """In-memory OpenCanary observation store for tests."""

    def __init__(self) -> None:
        self._observations: list[OpenCanaryObservation] = []

    def add(self, observation: OpenCanaryObservation) -> OpenCanaryObservation:
        self._observations.append(observation)
        return observation

    def list_recent(self, limit: int = 100) -> Iterable[OpenCanaryObservation]:
        return tuple(self._observations[-limit:])


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
                    }
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
                    }
                },
            ),
            AssetDefinition(
                asset_id="ops-db",
                asset_name="Operations Database",
                exposure_type="internal",
                interaction_level="medium",
                covers_tactics=["Credential Access", "Collection"],
                dependencies=["git-internal"],
            ),
            AssetDefinition(
                asset_id="admin-jumpbox",
                asset_name="Admin Jumpbox",
                exposure_type="internal",
                interaction_level="high",
                covers_tactics=["Lateral Movement", "Privilege Escalation"],
                dependencies=["git-internal"],
            ),
        ]

    def list_all(self) -> Iterable[AssetDefinition]:
        return tuple(self._assets)


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
