"""Technique-informed decision logic for choosing the next assets to expose.

The controller keeps asset exposure explainable: profile evidence creates a
set of strongly observed ATT&CK techniques, an ATT&CK group prior recommends
nearby technique directions, and the catalogue decides which concrete assets
can plausibly test those directions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from libs.common.attack import same_technique_family
from libs.common.attack import technique_family
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.common.json_utils import string_or_none
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
    TechniquePriorRepository,
)


@dataclass(frozen=True)
class CandidateScore:
    """Controller-local score bundle for one candidate asset.

    Example:
        CandidateScore(asset=git, strategy="exploit", candidate_type="recommended", selected_technique="T1213")
    """

    asset: AssetDefinition
    strategy: str
    candidate_type: str
    selected_technique: str | None
    technique_signal_score: float
    confidence_score: float
    recommendation_support: float
    expected_technique_gain: float
    telemetry_value: float
    matched_dependency_marker_count: int = 0
    technique_match_type: str = "none"
    matched_profile_technique: str | None = None
    matched_prior_technique: str | None = None
    upgrade_context: dict[str, Any] = field(default_factory=dict)
    matched_dependency_markers: tuple[str, ...] = field(default_factory=tuple)
    asset_group: str = "unknown"
    covered_techniques: tuple[str, ...] = field(default_factory=tuple)
    action_type: ActionType = ActionType.unlock
    configuration_id: str | None = None
    configuration_kind: str | None = None
    target_asset_id: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RevealOption:
    """Unified controller input for either an asset unlock or configuration reveal.

    Example:
        unlock git-internal and configure git-internal with git-db-credential-clue
        both become RevealOption objects before technique scoring.
    """

    asset: AssetDefinition
    action_type: ActionType
    covered_techniques: tuple[str, ...]
    telemetry_value: float
    matched_dependency_markers: tuple[str, ...] = field(default_factory=tuple)
    asset_group: str = "unknown"
    candidate_type_override: str | None = None
    upgrade_context: dict[str, Any] = field(default_factory=dict)
    configuration_id: str | None = None
    configuration_kind: str | None = None
    target_asset_id: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SelectionProfileView:
    """Typed read view over `default_settings.selection_profile`.

    Example:
        SelectionProfileView.from_asset(asset).asset_group -> "developer"
    """

    raw: dict[str, Any]
    template_family: str | None = None

    @classmethod
    def from_asset(cls, asset: AssetDefinition) -> "SelectionProfileView":
        value = asset.default_settings.get("selection_profile")
        return cls(
            raw=value if isinstance(value, dict) else {},
            template_family=asset.template_family,
        )

    @property
    def asset_group(self) -> str:
        value = self.raw.get("asset_group")
        return str(value or self.template_family or "unknown")

    @property
    def covered_techniques(self) -> list[str]:
        value = self.raw.get("covered_techniques")
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str) and item]

    @property
    def telemetry_value(self) -> float:
        value = self.raw.get("telemetry_value")
        if isinstance(value, (int, float)):
            return max(0.0, min(1.0, float(value)))
        if isinstance(value, str):
            return {"low": 0.25, "medium": 0.55, "high": 0.85}.get(value.lower(), 0.5)
        return 0.5

    @property
    def implementation_status(self) -> str:
        value = self.raw.get("implementation_status")
        return str(value or "ready")

    @property
    def optional_dependency_signals(self) -> dict[str, Any]:
        value = self.raw.get("optional_dependency_signals")
        return value if isinstance(value, dict) else {}

    @property
    def upgrade_candidates(self) -> list[dict[str, Any]]:
        value = self.raw.get("upgrade_candidates")
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


class ControllerService:
    """Exposure controller with group-prior recommendation plus catalogue gating."""

    def __init__(
        self,
        asset_repository: AssetRepository,
        technique_prior_repository: TechniquePriorRepository,
        config: RuntimeConfig | None = None,
    ) -> None:
        self._asset_repository = asset_repository
        self._technique_prior_repository = technique_prior_repository
        self._config = config or RuntimeConfig()

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
        strong_observed = self._strong_observed_techniques(request.profile)
        recommendations = self._technique_prior_repository.recommend(
            strong_observed,
            top_k=self._config.recommendation_top_k,
            support_threshold=self._config.recommendation_support_threshold,
        )

        if _scanner_only_profile(request.profile):
            return self._noop_response(
                request=request,
                reason="no_reveal: scanner-like traffic without follow-up context",
            )

        # Run main reveal first, then a constrained plausible explore pass.
        exploit_context: CandidateScore | None = None
        for strategy in ("exploit", "explore"):
            options = self._reveal_options(
                assets,
                request,
                planned_unlocked_asset_ids=planned_unlocked_asset_ids,
                rejected=rejected,
            )
            candidates = []
            for option in options:
                candidate = self._score_reveal_option(
                    option,
                    request,
                    strategy=strategy,
                    exploit_context=exploit_context,
                    strong_observed=strong_observed,
                    recommendations=recommendations,
                )
                if candidate is not None:
                    candidates.append(candidate)
            considered.extend(candidates)
            selected = min(candidates, key=_candidate_order_key) if candidates else None
            if selected is None:
                if strategy == "exploit" and not actions:
                    return self._noop_response(
                        request=request,
                        reason="no_reveal: no eligible asset for observed or recommended techniques",
                        candidate_asset_ids=self._candidate_asset_ids(considered),
                        rejected=rejected,
                    )
                continue

            actions.append(self._build_action(request.binding_id, selected))
            decisions.append(
                self._build_decision_event(
                    request,
                    selected,
                    rejected,
                    eligible_asset_ids=self._candidate_asset_ids(candidates),
                )
            )
            if selected.action_type == ActionType.unlock:
                planned_unlocked_asset_ids.append(selected.asset.asset_id)
            elif selected.target_asset_id:
                planned_unlocked_asset_ids.append(selected.target_asset_id)
            if strategy == "exploit":
                exploit_context = selected

        return ControllerTickResponse(
            binding_id=request.binding_id,
            actions=actions,
            decision_events=decisions,
            candidate_asset_ids=self._candidate_asset_ids(considered),
        )

    def _reveal_options(
        self,
        assets: list[AssetDefinition],
        request: ControllerTickRequest,
        *,
        planned_unlocked_asset_ids: list[str],
        rejected: dict[str, str],
    ) -> list[RevealOption]:
        """Return every reveal candidate before technique scoring.

        Asset unlocks and follow-on configuration reveals share the same scoring
        path after this point; only the final action type differs.
        """
        options: list[RevealOption] = []
        for asset in assets:
            eligible, reason = self._eligibility(asset, request, planned_unlocked_asset_ids)
            if not eligible:
                rejected[asset.asset_id] = reason
                continue
            option = self._asset_reveal_option(
                asset,
                request,
                all_assets=assets,
                unlocked_asset_ids=planned_unlocked_asset_ids,
            )
            if option is not None:
                options.append(option)
        options.extend(
            self._configuration_reveal_options(
                assets,
                request,
                planned_unlocked_asset_ids=planned_unlocked_asset_ids,
            )
        )
        return options

    def _asset_reveal_option(
        self,
        asset: AssetDefinition,
        request: ControllerTickRequest,
        *,
        all_assets: list[AssetDefinition],
        unlocked_asset_ids: list[str],
    ) -> RevealOption | None:
        selection_profile = SelectionProfileView.from_asset(asset)
        covered_techniques = selection_profile.covered_techniques
        if not covered_techniques:
            return None
        matched_markers = self._matched_dependency_markers(asset, request)
        return RevealOption(
            asset=asset,
            action_type=ActionType.unlock,
            covered_techniques=tuple(covered_techniques),
            telemetry_value=selection_profile.telemetry_value,
            matched_dependency_markers=tuple(matched_markers),
            asset_group=selection_profile.asset_group,
            upgrade_context=_upgrade_context(
                asset,
                all_assets,
                unlocked_asset_ids=unlocked_asset_ids,
                matched_markers=matched_markers,
            ),
        )

    def _configuration_reveal_options(
        self,
        assets: list[AssetDefinition],
        request: ControllerTickRequest,
        *,
        planned_unlocked_asset_ids: list[str],
    ) -> list[RevealOption]:
        """Return explicit follow-on configuration options for opened assets.

        Configuration variants are catalog-owned. They only appear here when
        the source asset is already open, the attacker is still on that source
        asset's active path, and the current profile matches an exact marker.
        """
        asset_by_id = {asset.asset_id: asset for asset in assets}
        observed = _observed_signal_sets(request)
        active_asset_ids = set(request.profile.recent_asset_ids)
        options: list[RevealOption] = []

        for source_asset in assets:
            if source_asset.asset_id not in request.unlocked_asset_ids:
                continue
            revealed_for_asset = set(
                request.revealed_configurations.get(source_asset.asset_id, [])
            )
            for variant in _configuration_variants(source_asset):
                configuration_id = string_or_none(variant.get("configuration_id"))
                if configuration_id is None or configuration_id in revealed_for_asset:
                    continue
                if not _variant_visible_on_active_path(
                    source_asset.asset_id,
                    variant,
                    active_asset_ids,
                ):
                    continue
                matched_markers = _matched_variant_markers(variant, observed)
                if _variant_required_markers(variant) and not matched_markers:
                    continue

                target_asset_id = string_or_none(variant.get("target_asset_id"))
                target_asset = asset_by_id.get(target_asset_id) if target_asset_id else None
                if target_asset_id and (
                    target_asset is None or target_asset_id in planned_unlocked_asset_ids
                ):
                    continue
                if target_asset is not None and not self._runtime_is_available(target_asset):
                    continue

                covered_techniques = _variant_covered_techniques(
                    variant,
                    target_asset or source_asset,
                )
                target_public_port = variant.get("public_port")
                upgrade_context = {}
                if target_asset is not None:
                    upgrade_context = {
                        "previous_backend_asset": source_asset.asset_id,
                        "upgraded_backend_asset": target_asset.asset_id,
                        "public_port": target_public_port,
                        "matched_markers": matched_markers,
                        "reason": variant.get("reason", ""),
                    }

                telemetry_value = _variant_telemetry_value(
                    variant,
                    target_asset or source_asset,
                )
                options.append(
                    RevealOption(
                        asset=source_asset,
                        action_type=ActionType.configure,
                        covered_techniques=tuple(covered_techniques),
                        telemetry_value=telemetry_value,
                        matched_dependency_markers=tuple(matched_markers),
                        asset_group=SelectionProfileView.from_asset(
                            target_asset or source_asset
                        ).asset_group,
                        candidate_type_override="configuration",
                        upgrade_context=upgrade_context,
                        configuration_id=configuration_id,
                        configuration_kind=string_or_none(variant.get("kind")),
                        target_asset_id=target_asset_id,
                        configuration=dict(variant),
                    )
                )
        return options

    def _score_reveal_option(
        self,
        option: RevealOption,
        request: ControllerTickRequest,
        *,
        strategy: str,
        exploit_context: CandidateScore | None,
        strong_observed: set[str],
        recommendations: dict[str, float],
    ) -> CandidateScore | None:
        """Classify one reveal option against observed and recommended techniques.

        Example:
            Input:
                option covers ["T1213"], prior recommends T1213=0.4
            Output:
                CandidateScore(candidate_type="recommended", selected_technique="T1213", ...)
        """
        profile = request.profile
        if not option.covered_techniques:
            return None

        technique_scores = {
            technique: self._technique_candidate_parts(
                technique,
                profile.conf_by_technique,
                strong_observed,
                recommendations,
            )
            for technique in option.covered_techniques
        }
        if option.action_type == ActionType.unlock and _is_bootstrap_asset(option.asset, request):
            # The internal portal is the first internal question. It needs
            # concrete evidence, but it should not require a CF recommendation.
            technique_scores = {
                technique: {
                    **parts,
                    "signal_score": 1.0,
                    "candidate_type": "bootstrap",
                }
                for technique, parts in technique_scores.items()
            }
        technique_scores = {
            technique: parts
            for technique, parts in technique_scores.items()
            if str(parts["candidate_type"]) != "none" and float(parts["signal_score"]) > 0
        }
        if not technique_scores:
            return None

        selected_technique, selected_parts = max(
            technique_scores.items(),
            key=lambda item: (
                _technique_gain(item[0], profile.conf_by_technique, recommendations),
                float(item[1]["signal_score"]),
                item[0],
            ),
        )
        technique_signal_score = float(selected_parts["signal_score"])
        confidence_score = float(selected_parts["confidence"])
        recommendation_support = float(selected_parts["recommendation_support"])
        candidate_type = option.candidate_type_override or str(selected_parts["candidate_type"])
        technique_match_type = str(selected_parts["match_type"])
        matched_profile_technique = string_or_none(selected_parts.get("matched_profile_technique"))
        matched_prior_technique = string_or_none(selected_parts.get("matched_prior_technique"))

        matched_markers = list(option.matched_dependency_markers)
        telemetry_value = option.telemetry_value
        expected_technique_gain = _expected_technique_gain(
            option.covered_techniques,
            profile.conf_by_technique,
            recommendations,
        )

        if strategy == "explore":
            if exploit_context is None:
                return None
            if same_technique_family(str(selected_technique), str(exploit_context.selected_technique)):
                return None
            if any(
                same_technique_family(str(selected_technique), covered)
                for covered in exploit_context.covered_techniques
            ):
                return None
            if len({technique_family(item) for item in strong_observed}) < 2:
                return None
            if not (_has_concrete_dependency_marker(matched_markers) or option.upgrade_context):
                return None

        return CandidateScore(
            asset=option.asset,
            strategy=strategy,
            candidate_type=candidate_type,
            selected_technique=selected_technique,
            technique_signal_score=round(technique_signal_score, 4),
            confidence_score=round(confidence_score, 4),
            recommendation_support=round(recommendation_support, 4),
            expected_technique_gain=round(expected_technique_gain, 4),
            telemetry_value=round(telemetry_value, 4),
            matched_dependency_marker_count=len(matched_markers),
            technique_match_type=technique_match_type,
            matched_profile_technique=matched_profile_technique,
            matched_prior_technique=matched_prior_technique,
            upgrade_context=option.upgrade_context,
            matched_dependency_markers=tuple(matched_markers),
            asset_group=option.asset_group,
            covered_techniques=option.covered_techniques,
            action_type=option.action_type,
            configuration_id=option.configuration_id,
            configuration_kind=option.configuration_kind,
            target_asset_id=option.target_asset_id,
            configuration=option.configuration,
        )

    def _technique_candidate_parts(
        self,
        technique: str,
        confidences: dict[str, float],
        strong_observed: set[str],
        recommendations: dict[str, float],
    ) -> dict[str, Any]:
        """Classify one technique as recommended, continuation, or unsupported.

        Example:
            Input:
                technique="T1059", recommendations={"T1059": 0.4}
            Output:
                {"candidate_type": "recommended", "signal_score": 0.4, ...}
        """
        current_confidence = float(confidences.get(technique, 0.0))
        recommendation_support = float(recommendations.get(technique, 0.0))
        matched_profile_technique = technique if current_confidence > 0 else None
        matched_prior_technique = technique if recommendation_support > 0 else None
        match_type = "exact" if current_confidence > 0 or recommendation_support > 0 else "none"
        family_confidence, family_confidence_technique = _best_family_score(technique, confidences)
        family_prior, family_prior_technique = _best_family_score(technique, recommendations)
        if family_confidence > current_confidence:
            current_confidence = family_confidence
            matched_profile_technique = family_confidence_technique
            match_type = "family"
        if family_prior > recommendation_support:
            recommendation_support = family_prior
            matched_prior_technique = family_prior_technique
            match_type = "family"
        strongly_observed = any(same_technique_family(technique, item) for item in strong_observed)
        candidate_type = "none"
        signal_score = 0.0
        if strongly_observed:
            candidate_type = "continuation"
            signal_score = min(1.0, current_confidence)
        elif recommendation_support > 0:
            candidate_type = "recommended"
            signal_score = recommendation_support
        return {
            "signal_score": signal_score,
            "confidence": current_confidence,
            "recommendation_support": recommendation_support,
            "candidate_type": candidate_type,
            "match_type": match_type,
            "matched_profile_technique": matched_profile_technique,
            "matched_prior_technique": matched_prior_technique,
        }

    def _strong_observed_techniques(self, profile) -> set[str]:
        return {
            technique
            for technique, confidence in profile.conf_by_technique.items()
            if float(confidence) >= self._config.strong_technique_threshold
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
        if SelectionProfileView.from_asset(asset).implementation_status not in {"ready", "prototype"}:
            return False, "asset not ready"
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
            if _signals_match(observed[key], required, key):
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
            SelectionProfileView.from_asset(asset).optional_dependency_signals,
        ):
            if not isinstance(signal_source, dict):
                continue
            for key, values in signal_source.items():
                if key not in observed or not isinstance(values, list):
                    continue
                for value in values:
                    if isinstance(value, str) and _signals_match(observed[key], {value}, key):
                        markers.append(f"{key}:{value}")
        return dedupe_preserve(markers)

    def _candidate_asset_ids(
        self,
        candidates: list[CandidateScore],
    ) -> list[str]:
        return dedupe_preserve([_candidate_exposed_asset_id(candidate) for candidate in candidates])

    def _build_action(
        self,
        binding_id: str,
        candidate: CandidateScore,
    ) -> ControllerAction:
        if candidate.action_type == ActionType.configure:
            return ControllerAction(
                action_type=ActionType.configure,
                binding_id=binding_id,
                asset_id=candidate.asset.asset_id,
                configuration_id=candidate.configuration_id,
                target_asset_id=candidate.target_asset_id,
                configuration=candidate.configuration,
                reason=(
                    f"{candidate.strategy} configured {candidate.asset.asset_id} "
                    f"with {candidate.configuration_id} for technique {candidate.selected_technique}"
                ),
            )
        return ControllerAction(
            action_type=ActionType.unlock,
            binding_id=binding_id,
            asset_id=candidate.asset.asset_id,
            reason=(
                f"{candidate.strategy} selected {candidate.asset.asset_id} "
                f"for technique {candidate.selected_technique}: "
                f"candidate_type={candidate.candidate_type}, "
                f"gain={candidate.expected_technique_gain}, telemetry={candidate.telemetry_value}"
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
            "reveal_role": _reveal_role(candidate.strategy),
            "candidate_type": candidate.candidate_type,
            "selected_technique": candidate.selected_technique,
            "technique_signal_score": candidate.technique_signal_score,
            "confidence_score": candidate.confidence_score,
            "recommendation_support": candidate.recommendation_support,
            "expected_technique_gain": candidate.expected_technique_gain,
            "technique_match_type": candidate.technique_match_type,
            "matched_profile_technique": candidate.matched_profile_technique,
            "matched_recommended_technique": candidate.matched_prior_technique,
            "telemetry_value": candidate.telemetry_value,
            "asset_group": candidate.asset_group,
            "covered_techniques": list(candidate.covered_techniques),
            "matched_dependency_markers": list(candidate.matched_dependency_markers),
            "matched_dependency_marker_count": candidate.matched_dependency_marker_count,
            "prior_degraded": self._technique_prior_repository.degraded_reason,
            "observed_techniques": sorted(self._strong_observed_techniques(request.profile)),
            "eligible_assets": eligible_asset_ids,
            "rejected_assets": dict(rejected),
            "ordering": _controller_ordering_details(candidate),
        }
        if candidate.action_type == ActionType.configure:
            details["configuration_reveal"] = {
                "asset_id": candidate.asset.asset_id,
                "configuration_id": candidate.configuration_id,
                "configuration_kind": candidate.configuration_kind,
                "target_asset_id": candidate.target_asset_id,
            }
        if candidate.upgrade_context:
            details["same_port_upgrade"] = candidate.upgrade_context
        decision_type = (
            DecisionType.configure
            if candidate.action_type == ActionType.configure
            else DecisionType.unlock
        )
        exposed_asset_id = _candidate_exposed_asset_id(candidate)
        return DecisionEvent(
            attacker_key=request.attacker_key,
            binding_id=request.binding_id,
            decision_type=decision_type,
            reason=(
                f"{candidate.strategy} selected {exposed_asset_id} "
                f"via {candidate.selected_technique}"
            ),
            trigger_evidence_ids=request.profile.recent_evidence_ids,
            asset_added=exposed_asset_id,
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
                        "prior_degraded": self._technique_prior_repository.degraded_reason,
                        "reveal_action": "no_reveal",
                        "no_reveal_reason": reason,
                        "rejected_assets": rejected or {},
                    },
                )
            ],
            candidate_asset_ids=candidate_asset_ids or [],
        )


def _best_family_score(
    technique: str,
    scores: dict[str, float],
) -> tuple[float, str | None]:
    """Return the best parent/sub-technique score with a conservative discount.

    Example:
        technique="T1552.001", scores={"T1552": 0.8} -> (0.6, "T1552")
    """
    best_score = 0.0
    best_technique: str | None = None
    for candidate, value in scores.items():
        if candidate == technique or not same_technique_family(candidate, technique):
            continue
        discounted = float(value) * 0.75
        if discounted > best_score:
            best_score = discounted
            best_technique = candidate
    return best_score, best_technique


def _expected_technique_gain(
    covered_techniques: tuple[str, ...],
    confidences: dict[str, float],
    recommendations: dict[str, float],
) -> float:
    """Return expected new technique gain for one reveal candidate.

    G(a) = sum p_t * (1 - C_t) over covered techniques. Prior support is the
    plausibility term; profile confidence only discounts techniques that are
    already strongly represented.
    """
    return sum(
        _technique_gain(technique, confidences, recommendations)
        for technique in covered_techniques
    )


def _technique_gain(
    technique: str,
    confidences: dict[str, float],
    recommendations: dict[str, float],
) -> float:
    """Return p_t * (1-C_t) for one technique family."""
    confidence = max(
        float(confidences.get(technique, 0.0)),
        _best_family_score(technique, confidences)[0],
    )
    support = max(
        float(recommendations.get(technique, 0.0)),
        _best_family_score(technique, recommendations)[0],
    )
    return support * max(0.0, 1.0 - confidence)


def _controller_ordering_details(candidate: CandidateScore) -> dict[str, Any]:
    """Return the deterministic ordering tuple used for an asset choice.

    Example:
        an asset with higher expected new technique gain sorts before a static
        telemetry-rich asset that mostly retests already-confident behavior.
    """
    return {
        "structural_priority_rank": _structural_priority_rank(candidate),
        "expected_technique_gain": candidate.expected_technique_gain,
        "matched_dependency_marker_count": candidate.matched_dependency_marker_count,
        "telemetry_value": candidate.telemetry_value,
        "asset_id": _candidate_exposed_asset_id(candidate),
    }


def _reveal_role(strategy: str) -> str:
    """Return the local choice role used by offline preference-choice evaluation."""
    return "explore" if strategy == "explore" else "main"


def _candidate_order_key(
    candidate: CandidateScore,
) -> tuple[float, float, int, float, str]:
    """Sort key for deterministic candidate ordering.

    Example:
        min(candidates, key=_candidate_order_key) returns the highest ranked
        candidate while keeping asset_id as an ascending tie-break.
    """
    return (
        -_structural_priority_rank(candidate),
        -candidate.expected_technique_gain,
        -candidate.matched_dependency_marker_count,
        -candidate.telemetry_value,
        _candidate_exposed_asset_id(candidate),
    )


def _structural_priority_rank(candidate: CandidateScore) -> int:
    """Return the two hard exceptions before expected-gain ordering."""
    if candidate.candidate_type == "bootstrap":
        return 2
    if candidate.action_type == ActionType.configure:
        return 1
    return 0


def _candidate_exposed_asset_id(candidate: CandidateScore) -> str:
    """Return the asset id that a decision exposes to the attacker."""
    return candidate.target_asset_id or candidate.asset.asset_id


def _has_concrete_dependency_marker(markers: list[str]) -> bool:
    """Return True when the reveal is backed by a concrete breadcrumb.

    Technique-only markers are useful for scoring, but explore reveals need a
    path, rule, or indicator so they do not branch from prior noise alone.
    """
    return any(not marker.startswith(("any_techniques:", "any_tactics:")) for marker in markers)


def _configuration_variants(asset: AssetDefinition) -> list[dict[str, Any]]:
    """Return catalog-declared follow-on configurations for one asset.

    Example:
        git-internal.default_settings.configuration_variants can expose a DB
        credential clue after repository browsing, without opening a new port.
    """
    value = asset.default_settings.get("configuration_variants")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _variant_required_markers(variant: dict[str, Any]) -> list[str]:
    value = variant.get("required_markers")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and ":" in item]


def _matched_variant_markers(
    variant: dict[str, Any],
    observed: dict[str, set[str]],
) -> list[str]:
    """Return exact configuration markers present in the current profile.

    Configuration reveals are narrower than asset unlocks, so technique
    markers are intentionally exact here instead of parent/sub-technique
    family matches.
    """
    markers: list[str] = []
    for marker in _variant_required_markers(variant):
        key, value = marker.split(":", 1)
        if key in observed and value in observed[key]:
            markers.append(marker)
    return dedupe_preserve(markers)


def _variant_visible_on_active_path(
    source_asset_id: str,
    variant: dict[str, Any],
    active_asset_ids: set[str],
) -> bool:
    """Return True when a configuration can appear on a currently active path.

    Example:
        source git-internal plus recent_asset_ids=["git-internal"] -> True.
        source git-internal plus recent_asset_ids=["finance-share"] -> False.
    """
    if not active_asset_ids:
        return False
    visible_from = variant.get("visible_from_asset_ids")
    allowed_asset_ids = {source_asset_id}
    if isinstance(visible_from, list):
        allowed_asset_ids.update(item for item in visible_from if isinstance(item, str))
    return bool(active_asset_ids.intersection(allowed_asset_ids))


def _variant_covered_techniques(
    variant: dict[str, Any],
    fallback_asset: AssetDefinition,
) -> list[str]:
    value = variant.get("covered_techniques")
    if isinstance(value, list):
        techniques = [item for item in value if isinstance(item, str) and item]
        if techniques:
            return techniques
    return SelectionProfileView.from_asset(fallback_asset).covered_techniques


def _variant_telemetry_value(
    variant: dict[str, Any],
    fallback_asset: AssetDefinition,
) -> float:
    value = variant.get("telemetry_value")
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return SelectionProfileView.from_asset(fallback_asset).telemetry_value


def _observed_signal_sets(request: ControllerTickRequest) -> dict[str, set[str]]:
    profile = request.profile
    return {
        "any_http_paths": set(profile.recent_public_http_paths),
        "any_http_rules": set(profile.recent_public_http_rules),
        "any_http_indicators": set(profile.recent_public_http_indicators),
        "any_internal_http_paths": set(profile.recent_internal_http_paths),
        "any_internal_http_rules": set(profile.recent_internal_http_rules),
        "any_internal_http_indicators": set(profile.recent_internal_http_indicators),
        "any_asset_ids": set(profile.recent_asset_ids),
        "any_techniques": set(profile.recent_techniques),
        "any_tactics": set(profile.recent_tactics),
    }


def _signals_match(observed: set[str], required: set[str], key: str) -> bool:
    if observed.intersection(required):
        return True
    if key != "any_techniques":
        return False
    return any(
        same_technique_family(observed_technique, required_technique)
        for observed_technique in observed
        for required_technique in required
    )


def _is_bootstrap_asset(asset: AssetDefinition, request: ControllerTickRequest) -> bool:
    if asset.asset_id != "internal-portal" or request.unlocked_asset_ids:
        return False
    profile = request.profile
    return bool(profile.recent_evidence_ids or profile.recent_techniques or profile.recent_tactics)


def _scanner_only_profile(profile) -> bool:
    """Return True when the short window only shows scanner-style probes.

    Example:
        recent technique T1190 plus no concrete breadcrumbs -> no_reveal.
    """
    techniques = set(profile.recent_techniques)
    if not techniques:
        return False
    scanner_techniques = {"T1190", "T1189", "T1046", "T1595", "T1595.001", "T1595.002", "T1595.003"}
    if not techniques.issubset(scanner_techniques):
        return False
    concrete_breadcrumbs = (
        profile.recent_public_http_indicators
        or profile.recent_public_http_rules
        or profile.recent_internal_http_indicators
        or profile.recent_internal_http_paths
        or profile.recent_internal_http_rules
    )
    return not bool(concrete_breadcrumbs)


def _upgrade_context(
    candidate: AssetDefinition,
    all_assets: list[AssetDefinition],
    *,
    unlocked_asset_ids: list[str],
    matched_markers: list[str],
) -> dict[str, Any]:
    """Return explicit same-port upgrade metadata when catalog allows it.

    Example:
        unlocked malware-sink declares upgrade candidate dionaea-capture -> context for dionaea-capture.
    """
    for source_asset in all_assets:
        if source_asset.asset_id not in unlocked_asset_ids:
            continue
        for upgrade in SelectionProfileView.from_asset(source_asset).upgrade_candidates:
            if upgrade.get("asset_id") != candidate.asset_id:
                continue
            required_markers = [
                marker
                for marker in upgrade.get("required_markers", [])
                if isinstance(marker, str)
            ]
            matched_required_markers = sorted(set(required_markers).intersection(matched_markers))
            if required_markers and not matched_required_markers:
                continue
            if matched_required_markers and not _has_concrete_dependency_marker(matched_required_markers):
                continue
            return {
                "previous_backend_asset": source_asset.asset_id,
                "upgraded_backend_asset": candidate.asset_id,
                "public_port": upgrade.get("public_port"),
                "reason": upgrade.get("reason", "explicit catalog upgrade candidate"),
                "matched_markers": matched_required_markers or matched_markers,
            }
    return {}
