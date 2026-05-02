"""Decision logic for choosing the next assets to expose.

This module scores candidate assets against the current attacker profile and
returns explainable exploit/explore actions for the orchestrator.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.contracts.models import (
    ActionType,
    AssetDefinition,
    ControllerAction,
    ControllerTickRequest,
    ControllerTickResponse,
    DecisionEvent,
    DecisionType,
)
from services.controller.repository import AssetRepository, TransitionRepository


@dataclass(frozen=True)
class CandidateScore:
    """Controller-local score bundle for one candidate asset.

    Example:
        CandidateScore(asset=portal, exploit_score=2.9, explore_score=1.1, procedure_score=0.7)
    """

    asset: AssetDefinition
    exploit_score: float
    explore_score: float
    procedure_score: float


class ControllerService:
    """MVP exposure controller with explainable exploit/explore scoring."""

    def __init__(
        self,
        asset_repository: AssetRepository,
        transition_repository: TransitionRepository,
        config: RuntimeConfig | None = None,
        rng: random.Random | None = None,
    ) -> None:
        self._asset_repository = asset_repository
        self._transition_repository = transition_repository
        self._config = config or RuntimeConfig()
        self._rng = rng or random.Random()

    def tick(self, request: ControllerTickRequest) -> ControllerTickResponse:
        # Tests may inject assets directly; otherwise use the catalog.
        assets = request.assets or list(self._asset_repository.list_all())
        # This is intentionally mutable during one tick. If the first selected
        # asset unlocks a dependency, the second pass can immediately consider
        # assets that depend on it instead of waiting for the next loop tick.
        planned_unlocked_asset_ids = list(request.unlocked_asset_ids)
        actions: list[ControllerAction] = []
        decisions: list[DecisionEvent] = []
        # Keep every candidate set we considered so the dashboard can show why
        # an asset was or was not available to the controller.
        candidate_scores: list[CandidateScore] = []

        # Run the preferred strategy first, then the opposite strategy. This
        # keeps exploit/explore behavior simple while still allowing one tick
        # to open a small chain such as internal-portal -> finance-share.
        first_strategy = (
            "exploit" if self._rng.random() >= self._config.epsilon else "explore"
        )
        strategies = [
            first_strategy,
            "explore" if first_strategy == "exploit" else "exploit",
        ]

        for index, strategy in enumerate(strategies):
            # Eligibility is recomputed on each pass because dependencies may
            # have changed after an earlier action in the same controller tick.
            candidates = [
                self._score_asset(asset, request)
                for asset in assets
                if self._is_eligible(asset, request, planned_unlocked_asset_ids)
            ]
            candidate_scores.extend(candidates)
            if not candidates:
                if not actions:
                    return self._noop_response(
                        request=request,
                        reason="no eligible assets remained after dependency and unlock filtering",
                    )
                break

            selected = self._pick_best(candidates, strategy)
            # Only the first pass is allowed to fallback. The second pass either
            # finds a complementary asset or stops, which prevents noisy loops.
            if selected is None and index == 0:
                fallback_strategy = strategies[1]
                selected = self._pick_best(candidates, fallback_strategy)
                if selected is None:
                    return self._noop_response(
                        request=request,
                        reason=f"no candidate crossed the {strategy} or {fallback_strategy} threshold",
                        candidate_asset_ids=[
                            candidate.asset.asset_id for candidate in candidates
                        ],
                    )
                strategy = fallback_strategy
                strategies[1] = "explore" if strategy == "exploit" else "exploit"
            elif selected is None:
                break

            actions.append(
                self._build_unlock_action(request.binding_id, selected, strategy)
            )
            decisions.append(self._build_decision_event(request, selected, strategy))
            # Mark the selected asset as planned before the next pass so chained
            # dependencies can be satisfied within this same response.
            planned_unlocked_asset_ids.append(selected.asset.asset_id)

        return ControllerTickResponse(
            binding_id=request.binding_id,
            actions=actions,
            decision_events=decisions,
            candidate_asset_ids=self._candidate_asset_ids(candidate_scores),
        )

    def _score_asset(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
    ) -> CandidateScore:
        profile = request.profile
        recent_tactics = set(profile.recent_tactics)
        fit_recent = 1.0 if recent_tactics.intersection(asset.covers_tactics) else 0.0

        confidences = [
            profile.conf_by_tactic.get(tactic, 0.0) for tactic in asset.covers_tactics
        ]
        strength_match = sum(confidences) / len(confidences) if confidences else 0.0
        # Novelty rewards under-observed tactics.
        novelty = (
            sum(1.0 - confidence for confidence in confidences) / len(confidences)
            if confidences
            else 1.0
        )
        coverage_gain = sum(
            1 for tactic in asset.covers_tactics if profile.conf_by_tactic.get(tactic, 0.0) < 0.3
        )
        procedure_score = self._procedure_score(
            recent_tactics=request.profile.recent_tactics,
            asset=asset,
        )

        exploit_score = (2.0 * fit_recent) + strength_match + procedure_score
        explore_score = (1.5 * novelty) + (0.5 * coverage_gain) + (0.25 * procedure_score)
        return CandidateScore(
            asset=asset,
            exploit_score=round(exploit_score, 4),
            explore_score=round(explore_score, 4),
            procedure_score=round(procedure_score, 4),
        )

    def _procedure_score(
        self,
        recent_tactics: list[str],
        asset: AssetDefinition,
    ) -> float:
        # Use the strongest recent tactic-to-candidate transition score.
        scores = [
            self._transition_repository.score_transition(current_tactic, candidate_tactic)
            for current_tactic in recent_tactics
            for candidate_tactic in asset.covers_tactics
        ]
        return max(scores, default=0.0)

    def _is_eligible(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
        unlocked_asset_ids: list[str],
    ) -> bool:
        # Filter by exposure type, duplicates, unlock cap, dependencies, and profile signals.
        if asset.exposure_type != "internal":
            return False
        if asset.asset_id in unlocked_asset_ids:
            return False
        if len(unlocked_asset_ids) >= self._config.unlock_cap:
            return False
        if not set(asset.dependencies).issubset(unlocked_asset_ids):
            return False
        return self._matches_unlock_signals(asset, request)

    def _matches_unlock_signals(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
    ) -> bool:
        """Return whether profile evidence satisfies catalog unlock signals.

        Catalog entries may declare several signal groups, for example a
        suspicious public HTTP path or a local rule name. Matching any configured
        group is enough to unlock the asset once normal dependencies are met.
        """
        unlock_signals = asset.default_settings.get("unlock_signals")
        if not isinstance(unlock_signals, dict) or not unlock_signals:
            return True

        profile = request.profile
        # These keys deliberately mirror data/assets/catalog.json so the asset
        # catalog can stay declarative.
        observed = {
            "any_http_paths": set(profile.recent_public_http_paths),
            "any_http_rules": set(profile.recent_public_http_rules),
            "any_http_indicators": set(profile.recent_public_http_indicators),
            "any_internal_http_paths": set(profile.recent_internal_http_paths),
            "any_internal_http_rules": set(profile.recent_internal_http_rules),
            "any_internal_http_indicators": set(profile.recent_internal_http_indicators),
        }

        # Empty or malformed signal lists should not accidentally block legacy
        # assets that do not use the public-surface dependency model.
        configured_signal_keys = [
            key
            for key in observed
            if isinstance(unlock_signals.get(key), list) and unlock_signals[key]
        ]
        if not configured_signal_keys:
            return True

        for key in configured_signal_keys:
            required = {
                item for item in unlock_signals[key] if isinstance(item, str)
            }
            if observed[key].intersection(required):
                return True
        return False

    def _candidate_asset_ids(
        self,
        candidates: list[CandidateScore],
    ) -> list[str]:
        """Return candidate IDs once, preserving the order they became eligible."""
        return dedupe_preserve(
            [candidate.asset.asset_id for candidate in candidates]
        )

    def _pick_best(
        self,
        candidates: list[CandidateScore],
        strategy: str,
    ) -> CandidateScore | None:
        if not candidates:
            return None

        if strategy == "exploit":
            # Only unlock when the candidate clears the threshold.
            ranked = sorted(
                candidates,
                key=lambda candidate: (candidate.exploit_score, candidate.procedure_score),
                reverse=True,
            )
            return ranked[0] if ranked[0].exploit_score >= 2.2 else None

        ranked = sorted(
            candidates,
            key=lambda candidate: (candidate.explore_score, candidate.procedure_score),
            reverse=True,
        )
        return ranked[0] if ranked[0].explore_score >= 1.2 else None

    def _build_unlock_action(
        self,
        binding_id: str,
        candidate: CandidateScore,
        strategy: str,
    ) -> ControllerAction:
        return ControllerAction(
            action_type=ActionType.unlock,
            binding_id=binding_id,
            asset_id=candidate.asset.asset_id,
            reason=(
                f"{strategy} score for {candidate.asset.asset_id}: "
                f"exploit={candidate.exploit_score}, "
                f"explore={candidate.explore_score}, "
                f"procedure={candidate.procedure_score}"
            ),
        )

    def _build_decision_event(
        self,
        request: ControllerTickRequest,
        candidate: CandidateScore,
        strategy: str,
    ) -> DecisionEvent:
        return DecisionEvent(
            attacker_key=request.attacker_key,
            binding_id=request.binding_id,
            decision_type=DecisionType.unlock,
            reason=(
                f"{strategy} selected {candidate.asset.asset_id} "
                f"(exploit={candidate.exploit_score}, "
                f"explore={candidate.explore_score})"
            ),
            trigger_evidence_ids=request.profile.recent_evidence_ids,
            asset_added=candidate.asset.asset_id,
        )

    def _noop_response(
        self,
        request: ControllerTickRequest,
        reason: str,
        candidate_asset_ids: list[str] | None = None,
    ) -> ControllerTickResponse:
        # Keep noop explicit so "do nothing" stays traceable.
        return ControllerTickResponse(
            binding_id=request.binding_id,
            actions=[
                ControllerAction(
                    action_type=ActionType.noop,
                    binding_id=request.binding_id,
                    reason=reason,
                )
            ],
            decision_events=[
                DecisionEvent(
                    attacker_key=request.attacker_key,
                    binding_id=request.binding_id,
                    decision_type=DecisionType.noop,
                    reason=reason,
                    trigger_evidence_ids=request.profile.recent_evidence_ids,
                )
            ],
            candidate_asset_ids=candidate_asset_ids or [],
        )
