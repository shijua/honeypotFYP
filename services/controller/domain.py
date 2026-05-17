"""Technique-first decision logic for choosing the next assets to expose.

The controller keeps asset exposure explainable: public profile evidence and a
dataset-derived ATT&CK transition prior choose techniques, while the catalogue
decides which concrete assets are eligible to reveal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import random
from typing import Any

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
from services.controller.repository import (
    AssetRepository,
    NoopRevealFeedbackRepository,
    RevealFeedbackRepository,
    TransitionRepository,
)


@dataclass(frozen=True)
class CandidateScore:
    """Controller-local score bundle for one candidate asset.

    Example:
        CandidateScore(asset=git, strategy="exploit", selected_technique="T1213", asset_score=0.84)
    """

    asset: AssetDefinition
    strategy: str
    selected_technique: str | None
    technique_score: float
    confidence_score: float
    prior_score: float
    asset_score: float
    soft_dependency_score: float
    telemetry_value: float
    feedback_preference: float = 0.5
    contrast_score: float = 0.0
    uncertainty_score: float = 0.0
    coverage_gap: float = 1.0
    context_key: str = ""
    matched_dependency_markers: tuple[str, ...] = field(default_factory=tuple)
    asset_group: str = "unknown"
    covered_techniques: tuple[str, ...] = field(default_factory=tuple)


class ControllerService:
    """Exposure controller with public-prior technique scoring."""

    def __init__(
        self,
        asset_repository: AssetRepository,
        transition_repository: TransitionRepository,
        config: RuntimeConfig | None = None,
        rng: random.Random | None = None,
        feedback_repository: RevealFeedbackRepository | None = None,
    ) -> None:
        self._asset_repository = asset_repository
        self._transition_repository = transition_repository
        self._feedback_repository = feedback_repository or NoopRevealFeedbackRepository()
        self._config = config or RuntimeConfig()
        # Kept for backwards-compatible tests that inject a seeded RNG. The
        # final controller is deterministic and does not use random exploration.
        self._rng = rng or random.Random()

    def tick(self, request: ControllerTickRequest) -> ControllerTickResponse:
        """Score eligible assets and return unlock/noop actions for one profile tick.

        Example:
            Input:
                profile.recent_techniques=["T1552.001"], unlocked_asset_ids=[]
            Output:
                actions=[unlock internal-portal] when the bootstrap gate is satisfied.
        """
        assets = request.assets or list(self._asset_repository.list_all())
        planned_unlocked_asset_ids = list(request.unlocked_asset_ids)
        actions: list[ControllerAction] = []
        decisions: list[DecisionEvent] = []
        considered: list[CandidateScore] = []
        rejected: dict[str, str] = {}

        # Run exploit first, then a constrained plausible explore pass.
        exploit_context: CandidateScore | None = None
        for strategy in ("exploit", "explore"):
            candidates = []
            for asset in assets:
                eligible, reason = self._eligibility(asset, request, planned_unlocked_asset_ids)
                if not eligible:
                    rejected[asset.asset_id] = reason
                    continue
                candidate = self._score_asset(
                    asset,
                    request,
                    strategy=strategy,
                    exploit_context=exploit_context,
                )
                if candidate is not None:
                    candidates.append(candidate)
            considered.extend(candidates)
            selected = self._pick_best(candidates, strategy)
            if selected is None:
                if strategy == "exploit" and not actions:
                    return self._noop_response(
                        request=request,
                        reason="no eligible asset crossed the technique-first exploit threshold",
                        candidate_asset_ids=self._candidate_asset_ids(considered),
                        rejected=rejected,
                    )
                continue

            actions.append(self._build_unlock_action(request.binding_id, selected))
            decisions.append(
                self._build_decision_event(
                    request,
                    selected,
                    rejected,
                    eligible_asset_ids=self._candidate_asset_ids(candidates),
                )
            )
            planned_unlocked_asset_ids.append(selected.asset.asset_id)
            if strategy == "exploit":
                exploit_context = selected

        return ControllerTickResponse(
            binding_id=request.binding_id,
            actions=actions,
            decision_events=decisions,
            candidate_asset_ids=self._candidate_asset_ids(considered),
        )

    def _score_asset(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
        *,
        strategy: str,
        exploit_context: CandidateScore | None,
    ) -> CandidateScore | None:
        """Calculate exploit or explore score for a single eligible asset.

        Example:
            Input:
                asset covers ["T1213"], profile confidence T1213=0.8, prior T1213=0.4
            Output:
                CandidateScore(selected_technique="T1213", technique_score=0.64, ...)
        """
        profile = request.profile
        selection_profile = _selection_profile(asset)
        covered_techniques = _covered_techniques(asset)
        if not covered_techniques:
            return None

        next_scores = self._transition_repository.next_scores(
            profile.recent_techniques,
            self._config.transition_top_k,
        )
        technique_scores = {
            technique: self._technique_score_parts(
                technique,
                profile.conf_by_technique,
                next_scores,
            )
            for technique in covered_techniques
        }
        if _is_bootstrap_asset(asset, request):
            # The internal portal is the first internal question. It needs some
            # observed behaviour, but it should not require a prior transition.
            technique_scores = {
                technique: {
                    **parts,
                    "score": max(float(parts["score"]), 0.55),
                }
                for technique, parts in technique_scores.items()
            }

        selected_technique, selected_parts = max(
            technique_scores.items(),
            key=lambda item: (float(item[1]["score"]), item[0]),
        )
        technique_score = float(selected_parts["score"])
        confidence_score = float(selected_parts["confidence"])
        prior_score = float(selected_parts["prior"])
        if technique_score <= 0:
            return None

        matched_markers = self._matched_dependency_markers(asset, request)
        soft_dependency_score = self._soft_dependency_score(asset, request)
        telemetry_value = _telemetry_value(selection_profile)
        asset_group = str(selection_profile.get("asset_group") or asset.template_family or "unknown")
        context_key = _feedback_context_key(selected_technique, matched_markers)
        feedback_preference = self._feedback_repository.preference(context_key, asset_group)

        if strategy == "exploit":
            asset_score = (
                (0.50 * technique_score)
                + (0.30 * soft_dependency_score)
                + (0.20 * telemetry_value)
            )
            return CandidateScore(
                asset=asset,
                strategy=strategy,
                selected_technique=selected_technique,
                technique_score=round(technique_score, 4),
                confidence_score=round(confidence_score, 4),
                prior_score=round(prior_score, 4),
                asset_score=round(asset_score, 4),
                soft_dependency_score=round(soft_dependency_score, 4),
                telemetry_value=round(telemetry_value, 4),
                feedback_preference=round(feedback_preference, 4),
                context_key=context_key,
                matched_dependency_markers=tuple(matched_markers),
                asset_group=asset_group,
                covered_techniques=tuple(covered_techniques),
            )

        if exploit_context is None:
            return None
        if asset_group == exploit_context.asset_group:
            return None
        contrast = self._contrast_score(
            matched_markers,
            asset_group,
            exploit_context,
        )
        uncertainty = 1 - abs((2 * technique_score) - 1)
        coverage_gap = self._feedback_repository.coverage_gap(context_key, asset_group)
        asset_score = (
            (0.40 * technique_score)
            + (0.30 * contrast)
            + (0.20 * uncertainty)
            + (0.10 * coverage_gap)
        )
        return CandidateScore(
            asset=asset,
            strategy=strategy,
            selected_technique=selected_technique,
            technique_score=round(technique_score, 4),
            confidence_score=round(confidence_score, 4),
            prior_score=round(prior_score, 4),
            asset_score=round(asset_score, 4),
            soft_dependency_score=round(soft_dependency_score, 4),
            telemetry_value=round(telemetry_value, 4),
            feedback_preference=round(feedback_preference, 4),
            contrast_score=round(contrast, 4),
            uncertainty_score=round(uncertainty, 4),
            coverage_gap=round(coverage_gap, 4),
            context_key=context_key,
            matched_dependency_markers=tuple(matched_markers),
            asset_group=asset_group,
            covered_techniques=tuple(covered_techniques),
        )

    def _technique_score_parts(
        self,
        technique: str,
        confidences: dict[str, float],
        next_scores: dict[str, float],
    ) -> dict[str, float]:
        """Combine observed profile confidence with public transition prior.

        Example:
            Input:
                confidence=0.8, prior=0.4, exploit_lambda=0.6
            Output:
                {"score": 0.64, "confidence": 0.8, "prior": 0.4}
        """
        current_confidence = float(confidences.get(technique, 0.0))
        sequence_prior = float(next_scores.get(technique, 0.0))
        score = (
            self._config.exploit_lambda * current_confidence
            + (1 - self._config.exploit_lambda) * sequence_prior
        )
        return {
            "score": score,
            "confidence": current_confidence,
            "prior": sequence_prior,
        }

    def _eligibility(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
        unlocked_asset_ids: list[str],
    ) -> tuple[bool, str]:
        """Apply hard gates before an asset can be scored.

        Example:
            Input:
                asset.dependencies=["internal-portal"], unlocked_asset_ids=[]
            Output:
                (False, "missing dependencies: ['internal-portal']")
        """
        if asset.exposure_type != "internal":
            return False, "not an internal asset"
        if asset.asset_id in unlocked_asset_ids:
            return False, "already unlocked"
        if len(unlocked_asset_ids) >= self._config.unlock_cap:
            return False, "unlock cap reached"
        if not set(asset.dependencies).issubset(unlocked_asset_ids):
            return False, f"missing dependencies: {sorted(set(asset.dependencies) - set(unlocked_asset_ids))}"
        if not self._runtime_is_available(asset):
            return False, "runtime unavailable on this host"
        if _is_bootstrap_asset(asset, request):
            return (True, "bootstrap internal portal")
        if not self._matches_unlock_signals(asset, request):
            return False, "profile does not match unlock signals"
        return True, "eligible"

    def _runtime_is_available(self, asset: AssetDefinition) -> bool:
        runtime = asset.default_settings.get("runtime")
        if not isinstance(runtime, dict):
            return True
        if runtime.get("backend") != "compose":
            return True
        compose_file = runtime.get("compose_file")
        if not isinstance(compose_file, str) or not compose_file:
            return False
        return Path(compose_file).exists()

    def _matches_unlock_signals(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
    ) -> bool:
        """Check whether the profile contains any hard unlock signal for an asset.

        Example:
            Input:
                unlock_signals={"any_techniques": ["T1005"]}, profile.recent_techniques=["T1005"]
            Output:
                True
        """
        unlock_signals = asset.default_settings.get("unlock_signals")
        if not isinstance(unlock_signals, dict) or not unlock_signals:
            return bool(request.profile.recent_evidence_ids or request.profile.recent_techniques)

        observed = _observed_signal_sets(request)
        configured_signal_keys = [
            key
            for key in observed
            if isinstance(unlock_signals.get(key), list) and unlock_signals[key]
        ]
        if not configured_signal_keys:
            return True

        for key in configured_signal_keys:
            required = {item for item in unlock_signals[key] if isinstance(item, str)}
            if observed[key].intersection(required):
                return True
        return False

    def _matched_dependency_markers(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
    ) -> list[str]:
        """Return the concrete signal markers that matched hard or soft dependencies.

        Example:
            Input:
                observed any_http_indicators={"path:.bak"}, asset wants ["path:.bak"]
            Output:
                ["any_http_indicators:path:.bak"]
        """
        observed = _observed_signal_sets(request)
        markers: list[str] = []
        for signal_source in (
            asset.default_settings.get("unlock_signals"),
            _selection_profile(asset).get("optional_dependency_signals"),
        ):
            if not isinstance(signal_source, dict):
                continue
            for key, values in signal_source.items():
                if key not in observed or not isinstance(values, list):
                    continue
                for value in values:
                    if isinstance(value, str) and value in observed[key]:
                        markers.append(f"{key}:{value}")
        return dedupe_preserve(markers)

    def _soft_dependency_score(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
    ) -> float:
        """Return the fraction of optional dependency signals seen in the profile.

        Example:
            Input:
                optional signals ["path:.bak", "path:admin"], observed {"path:.bak"}
            Output:
                0.5
        """
        optional_signals = _selection_profile(asset).get("optional_dependency_signals")
        if not isinstance(optional_signals, dict) or not optional_signals:
            optional_signals = asset.default_settings.get("unlock_signals")
        if not isinstance(optional_signals, dict) or not optional_signals:
            return 0.0

        observed = _observed_signal_sets(request)
        total = 0
        matched = 0
        for key, values in optional_signals.items():
            if key not in observed or not isinstance(values, list):
                continue
            string_values = [value for value in values if isinstance(value, str)]
            total += len(string_values)
            matched += sum(1 for value in string_values if value in observed[key])
        return matched / total if total else 0.0

    def _contrast_score(
        self,
        markers: list[str],
        asset_group: str,
        exploit_context: CandidateScore,
    ) -> float:
        """Score how plausible-but-different an explore asset is from exploit.

        Example:
            Input:
                same dependency marker, different asset_group
            Output:
                1.0
        """
        marker_overlap = _jaccard(set(markers), set(exploit_context.matched_dependency_markers))
        if not markers and not exploit_context.matched_dependency_markers:
            marker_overlap = 0.5
        group_overlap = 1.0 if asset_group == exploit_context.asset_group else 0.0
        return marker_overlap * (1 - group_overlap)

    def _candidate_asset_ids(
        self,
        candidates: list[CandidateScore],
    ) -> list[str]:
        return dedupe_preserve([candidate.asset.asset_id for candidate in candidates])

    def _pick_best(
        self,
        candidates: list[CandidateScore],
        strategy: str,
    ) -> CandidateScore | None:
        if not candidates:
            return None
        ranked = sorted(
            candidates,
            key=lambda candidate: (
                candidate.asset_score,
                candidate.technique_score,
                candidate.soft_dependency_score,
                candidate.asset.asset_id,
            ),
            reverse=True,
        )
        threshold = 0.25 if strategy == "exploit" else 0.20
        return ranked[0] if ranked[0].asset_score >= threshold else None

    def _build_unlock_action(
        self,
        binding_id: str,
        candidate: CandidateScore,
    ) -> ControllerAction:
        return ControllerAction(
            action_type=ActionType.unlock,
            binding_id=binding_id,
            asset_id=candidate.asset.asset_id,
            reason=(
                f"{candidate.strategy} selected {candidate.asset.asset_id} "
                f"for technique {candidate.selected_technique}: "
                f"asset_score={candidate.asset_score}, technique_score={candidate.technique_score}, "
                f"soft_dependency={candidate.soft_dependency_score}, telemetry={candidate.telemetry_value}"
            ),
        )

    def _build_decision_event(
        self,
        request: ControllerTickRequest,
        candidate: CandidateScore,
        rejected: dict[str, str],
        *,
        eligible_asset_ids: list[str],
    ) -> DecisionEvent:
        details = {
            "strategy": candidate.strategy,
            "selected_strategy": candidate.strategy,
            "selected_technique": candidate.selected_technique,
            "technique_score": candidate.technique_score,
            "confidence_score": candidate.confidence_score,
            "prior_score": candidate.prior_score,
            "asset_score": candidate.asset_score,
            "soft_dependency_score": candidate.soft_dependency_score,
            "telemetry_value": candidate.telemetry_value,
            "feedback_preference": candidate.feedback_preference,
            "asset_group": candidate.asset_group,
            "covered_techniques": list(candidate.covered_techniques),
            "matched_dependency_markers": list(candidate.matched_dependency_markers),
            "feedback_context_key": candidate.context_key,
            "contrast_score": candidate.contrast_score,
            "uncertainty_score": candidate.uncertainty_score,
            "coverage_gap": candidate.coverage_gap,
            "dataset_prior_degraded": self._transition_repository.degraded_reason,
            "eligible_assets": eligible_asset_ids,
            "rejected_assets": rejected,
        }
        return DecisionEvent(
            attacker_key=request.attacker_key,
            binding_id=request.binding_id,
            decision_type=DecisionType.unlock,
            reason=(
                f"{candidate.strategy} selected {candidate.asset.asset_id} "
                f"via {candidate.selected_technique}"
            ),
            trigger_evidence_ids=request.profile.recent_evidence_ids,
            asset_added=candidate.asset.asset_id,
            details=details,
        )

    def _noop_response(
        self,
        request: ControllerTickRequest,
        reason: str,
        candidate_asset_ids: list[str] | None = None,
        rejected: dict[str, str] | None = None,
    ) -> ControllerTickResponse:
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
                    details={
                        "dataset_prior_degraded": self._transition_repository.degraded_reason,
                        "rejected_assets": rejected or {},
                    },
                )
            ],
            candidate_asset_ids=candidate_asset_ids or [],
        )


def _selection_profile(asset: AssetDefinition) -> dict[str, Any]:
    value = asset.default_settings.get("selection_profile")
    return value if isinstance(value, dict) else {}


def _covered_techniques(asset: AssetDefinition) -> list[str]:
    value = _selection_profile(asset).get("covered_techniques")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _telemetry_value(selection_profile: dict[str, Any]) -> float:
    value = selection_profile.get("telemetry_value")
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    if isinstance(value, str):
        return {"low": 0.25, "medium": 0.55, "high": 0.85}.get(value.lower(), 0.5)
    return 0.5


def _observed_signal_sets(request: ControllerTickRequest) -> dict[str, set[str]]:
    profile = request.profile
    return {
        "any_http_paths": set(profile.recent_public_http_paths),
        "any_http_rules": set(profile.recent_public_http_rules),
        "any_http_indicators": set(profile.recent_public_http_indicators),
        "any_internal_http_paths": set(profile.recent_internal_http_paths),
        "any_internal_http_rules": set(profile.recent_internal_http_rules),
        "any_internal_http_indicators": set(profile.recent_internal_http_indicators),
        "any_techniques": set(profile.recent_techniques),
        "any_tactics": set(profile.recent_tactics),
    }


def _is_bootstrap_asset(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
    if asset.asset_id != "internal-portal" or request.unlocked_asset_ids:
        return False
    profile = request.profile
    return bool(profile.recent_evidence_ids or profile.recent_techniques or profile.recent_tactics)


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left and not right:
        return 0.0
    return len(left & right) / len(left | right)


def _feedback_context_key(technique: str | None, markers: list[str]) -> str:
    """Build the stable feedback bucket key for one reveal context.

    Example:
        ("T1552.001", ["any_http_indicators:path:.bak"]) -> "T1552.001|any_http_indicators:path:.bak"
    """
    parts = [technique or "unknown", *sorted(markers)]
    return "|".join(parts)
