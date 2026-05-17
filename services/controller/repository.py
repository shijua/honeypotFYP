"""Repository adapters for controller inputs.

The controller consumes two durable inputs:
- the asset catalog it may expose
- a public-dataset technique transition prior used for next-technique scoring
"""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any, Protocol

from libs.common.clock import utcnow
from libs.common.json_store import JsonFileStore
from libs.common.json_utils import mutable_nested_dict
from libs.contracts.models import AssetDefinition


class AssetRepository(Protocol):
    """Storage contract for the controller asset catalog.

    Example:
        list_all() -> [AssetDefinition(asset_id="internal-portal", ...)]
    """

    def list_all(self) -> Iterable[AssetDefinition]:
        """Return the template catalog available to the controller."""
        ...


class TransitionRepository(Protocol):
    """Lookup contract for ATT&CK technique transition support.

    Example:
        next_scores(["T1552.001"], 5) -> {"T1213": 0.64, "T1046": 0.36}
    """

    @property
    def degraded_reason(self) -> str | None:
        """Return why the prior is unavailable, or None when healthy."""
        ...

    def score_transition(self, current_technique: str, candidate_technique: str) -> float:
        """Return P(candidate_technique | current_technique), or 0 if unknown."""
        ...

    def next_scores(self, recent_techniques: list[str], top_k: int) -> dict[str, float]:
        """Return recency-weighted next-technique scores for a profile sequence."""
        ...


class RevealFeedbackRepository(Protocol):
    """Lookup and persistence contract for reveal choice feedback.

    Example:
        coverage_gap("T1552.001|path:.bak", "archive") -> 0.67
    """

    def coverage_gap(self, context_key: str, asset_group: str) -> float:
        """Return how under-sampled one asset group is for this technique context."""
        ...

    def preference(self, context_key: str, asset_group: str) -> float:
        """Return a smoothed useful/revealed preference for one context/group pair."""
        ...

    def record_reveal(
        self,
        *,
        context_key: str,
        asset_group: str,
        binding_id: str,
        attacker_key: str,
        asset_id: str,
        available_assets: list[str] | None = None,
        revealed_assets: list[str] | None = None,
    ) -> None:
        """Record that the controller revealed an asset for later outcome scoring."""
        ...

    def record_outcome(
        self,
        *,
        context_key: str,
        asset_group: str,
        outcome: str,
    ) -> None:
        """Record a follow-up outcome such as useful, shallow, or ignored."""
        ...


class FileAssetRepository:
    """JSON-backed asset catalog used by the default controller runtime."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def list_all(self) -> Iterable[AssetDefinition]:
        with self._path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return tuple(AssetDefinition.model_validate(item) for item in payload)


class FileTechniqueTransitionRepository:
    """File-backed public ATT&CK technique transition prior.

    Example:
        Input file:
            {"transitions": {"T1552.001": {"T1213": {"probability": 0.7, "support": 3}}},
             "order2_transitions": {"T1083|T1552.001": {"T1213": {"probability": 0.9, "support": 2}}},
             "order3_transitions": {"T1046|T1083|T1552.001": {"T1213": {"probability": 0.95, "support": 3}}}}
        Output:
            score_transition("T1552.001", "T1213") == 0.7
    """

    def __init__(
        self,
        path: str | Path,
        min_support: int = 1,
        order2_min_support: int = 2,
        order3_min_support: int = 3,
    ) -> None:
        self._path = Path(path)
        self._min_support = min_support
        self._order2_min_support = order2_min_support
        self._order3_min_support = order3_min_support
        self._transitions: dict[str, dict[str, dict[str, Any]]] = {}
        self._order2_transitions: dict[str, dict[str, dict[str, Any]]] = {}
        self._order3_transitions: dict[str, dict[str, dict[str, Any]]] = {}
        self._degraded_reason: str | None = None
        self._load()

    @property
    def degraded_reason(self) -> str | None:
        return self._degraded_reason

    def score_transition(self, current_technique: str, candidate_technique: str) -> float:
        """Return one direct transition probability, respecting min-support.

        Example:
            Input:
                current_technique="T1552.001", candidate_technique="T1213"
            Output:
                0.7 when the prior has T1552.001 -> T1213 probability 0.7
        """
        payload = self._transitions.get(current_technique, {}).get(candidate_technique)
        if not isinstance(payload, dict):
            return 0.0
        if not payload.get("fallback") and int(payload.get("support", payload.get("count", 0)) or 0) < self._min_support:
            return 0.0
        try:
            return float(payload.get("probability", 0.0))
        except (TypeError, ValueError):
            return 0.0

    def next_scores(self, recent_techniques: list[str], top_k: int) -> dict[str, float]:
        """Return max recency-weighted transition probability per destination.

        The newest technique receives weight 1.0, the previous one 0.5, then
        0.333..., so older profile context can help but cannot dominate. When
        supported higher-order context exists, the score is only boosted:
        order2_score = max(base, 0.60*P(next|current) + 0.25*P(next|previous,current) + 0.15*base)
        order3_score = max(order2_score, 0.45*P(next|current) + 0.20*P(next|previous,current) + 0.25*P(next|previous2,previous,current) + 0.10*order2_score)

        Example:
            Input:
                recent_techniques=["T1083", "T1552.001"], top_k=2
            Output:
                {"T1213": 0.75, "T1046": 0.3}
        """
        scores = self._order1_scores(recent_techniques, top_k)
        recent = [technique for technique in recent_techniques if technique]
        if len(recent) >= 2:
            previous, current = recent[-2], recent[-1]
            order2_scores = self._order2_scores(previous, current)
            if order2_scores:
                for candidate in set(scores) | set(order2_scores):
                    base_score = scores.get(candidate, 0.0)
                    current_probability = self.score_transition(current, candidate)
                    order2_probability = order2_scores.get(candidate, 0.0)
                    # Keep the order-1 score as the floor; order-2 context can
                    # raise a candidate but never make an existing rank worse.
                    hybrid_score = (0.60 * current_probability) + (0.25 * order2_probability) + (0.15 * base_score)
                    scores[candidate] = max(base_score, hybrid_score)
        if len(recent) >= 3:
            previous2, previous, current = recent[-3], recent[-2], recent[-1]
            order2_scores = self._order2_scores(previous, current)
            order3_scores = self._order3_scores(previous2, previous, current)
            if order3_scores:
                for candidate in set(scores) | set(order2_scores) | set(order3_scores):
                    base_score = scores.get(candidate, 0.0)
                    current_probability = self.score_transition(current, candidate)
                    order2_probability = order2_scores.get(candidate, 0.0)
                    order3_probability = order3_scores.get(candidate, 0.0)
                    # At this point base_score may already include the order-2
                    # boost above. The final max preserves that fallback if the
                    # third-order context is sparse or weaker.
                    hybrid_score = (
                        (0.45 * current_probability)
                        + (0.20 * order2_probability)
                        + (0.25 * order3_probability)
                        + (0.10 * base_score)
                    )
                    scores[candidate] = max(base_score, hybrid_score)
        return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:top_k])

    def _order1_scores(self, recent_techniques: list[str], top_k: int) -> dict[str, float]:
        """Return the original recency-weighted one-step transition scores.

        Example:
            Input:
                recent_techniques=["T1552.001", "T1046"], top_k=2
            Output:
                newest T1046 edges get weight 1.0; older T1552.001 edges get weight 0.5.
        """
        scores: dict[str, float] = {}
        recent = [technique for technique in recent_techniques if technique]
        for distance, technique in enumerate(reversed(recent[-top_k:]), start=1):
            weight = 1.0 / distance
            for candidate, payload in self._transitions.get(technique, {}).items():
                if not self._payload_has_support(payload, self._min_support, allow_fallback=True):
                    continue
                try:
                    probability = float(payload.get("probability", 0.0))
                except (TypeError, ValueError):
                    continue
                scores[candidate] = max(scores.get(candidate, 0.0), probability * weight)
        return scores

    def _order2_scores(self, previous_technique: str, current_technique: str) -> dict[str, float]:
        """Return supported P(next | previous,current) scores for the latest pair.

        Example:
            Input:
                previous_technique="T1083", current_technique="T1552.001"
            Output:
                {"T1213": 0.9} when order2_transitions has "T1083|T1552.001" with enough support.
        """
        source = f"{previous_technique}|{current_technique}"
        scores: dict[str, float] = {}
        for candidate, payload in self._order2_transitions.get(source, {}).items():
            if not self._payload_has_support(payload, self._order2_min_support, allow_fallback=False):
                continue
            try:
                scores[candidate] = float(payload.get("probability", 0.0))
            except (TypeError, ValueError):
                continue
        return scores

    def _order3_scores(self, previous2_technique: str, previous_technique: str, current_technique: str) -> dict[str, float]:
        """Return supported P(next | previous2,previous,current) scores.

        Example:
            Input:
                previous2_technique="T1046", previous_technique="T1083", current_technique="T1552.001"
            Output:
                {"T1213": 0.95} when order3_transitions has enough support.
        """
        source = f"{previous2_technique}|{previous_technique}|{current_technique}"
        scores: dict[str, float] = {}
        for candidate, payload in self._order3_transitions.get(source, {}).items():
            if not self._payload_has_support(payload, self._order3_min_support, allow_fallback=False):
                continue
            try:
                scores[candidate] = float(payload.get("probability", 0.0))
            except (TypeError, ValueError):
                continue
        return scores

    def _load(self) -> None:
        if not self._path.exists():
            self._degraded_reason = f"transition prior file missing: {self._path}"
            self._transitions = {}
            self._order2_transitions = {}
            self._order3_transitions = {}
            return
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as exc:
            self._degraded_reason = f"could not load transition prior {self._path}: {exc}"
            self._transitions = {}
            self._order2_transitions = {}
            self._order3_transitions = {}
            return
        transitions = payload.get("transitions") if isinstance(payload, dict) else None
        if not isinstance(transitions, dict):
            self._degraded_reason = f"transition prior has no transitions object: {self._path}"
            self._transitions = {}
            self._order2_transitions = {}
            self._order3_transitions = {}
            return
        self._transitions = {
            str(source): {
                str(destination): item
                for destination, item in destinations.items()
                if isinstance(item, dict)
            }
            for source, destinations in transitions.items()
            if isinstance(destinations, dict)
        }
        order2_transitions = payload.get("order2_transitions") if isinstance(payload, dict) else None
        self._order2_transitions = {
            str(source): {
                str(destination): item
                for destination, item in destinations.items()
                if isinstance(item, dict)
            }
            for source, destinations in order2_transitions.items()
            if isinstance(destinations, dict)
        } if isinstance(order2_transitions, dict) else {}
        order3_transitions = payload.get("order3_transitions") if isinstance(payload, dict) else None
        self._order3_transitions = {
            str(source): {
                str(destination): item
                for destination, item in destinations.items()
                if isinstance(item, dict)
            }
            for source, destinations in order3_transitions.items()
            if isinstance(destinations, dict)
        } if isinstance(order3_transitions, dict) else {}
        self._degraded_reason = None

    @staticmethod
    def _payload_has_support(payload: dict[str, Any], min_support: int, *, allow_fallback: bool) -> bool:
        """Return whether a transition payload can participate in scoring.

        Example:
            Input:
                payload={"support": 0, "fallback": True}, min_support=2, allow_fallback=True
            Output:
                True
        """
        if allow_fallback and payload.get("fallback"):
            return True
        return int(payload.get("support", payload.get("count", 0)) or 0) >= min_support


class FileRevealFeedbackRepository:
    """File-backed feedback store for adaptive reveal choices.

    Example:
        Input file:
            {"contexts": {"T1552.001|path:.bak": {"asset_groups": {"archive": {"revealed": 2, "useful": 1}}}}}
        Output:
            preference("T1552.001|path:.bak", "archive") == 0.5
    """

    def __init__(self, path: str | Path, target_useful: int = 3) -> None:
        self._store = JsonFileStore(path, default_data={"schema_version": "v1", "contexts": {}, "pending": []})
        self._target_useful = max(1, target_useful)

    def coverage_gap(self, context_key: str, asset_group: str) -> float:
        """Return how much more this context/group should be sampled.

        Example:
            Input:
                context_key="T1552.001|path:.bak", asset_group="archive", useful=1, target_useful=3
            Output:
                0.6667
        """
        group = self._group_record(context_key, asset_group)
        useful = int(group.get("useful", 0) or 0)
        return round(max(0.0, 1.0 - min(useful, self._target_useful) / self._target_useful), 4)

    def preference(self, context_key: str, asset_group: str) -> float:
        """Return smoothed useful/revealed preference for exploit-style ranking.

        Example:
            Input:
                revealed=2, useful=1
            Output:
                (1 + 1) / (2 + 2) == 0.5
        """
        group = self._group_record(context_key, asset_group)
        revealed = int(group.get("revealed", 0) or 0)
        useful = int(group.get("useful", 0) or 0)
        return round((useful + 1) / (revealed + 2), 4)

    def record_reveal(
        self,
        *,
        context_key: str,
        asset_group: str,
        binding_id: str,
        attacker_key: str,
        asset_id: str,
        available_assets: list[str] | None = None,
        revealed_assets: list[str] | None = None,
    ) -> None:
        """Record a reveal so a later touch can be marked useful or ignored.

        Example:
            Input:
                asset_id="finance-share", available_assets=["finance-share", "git-internal"]
            Output:
                pending contains one finance-share reveal for the attacker/binding.
        """
        payload = self._store.read()
        group = self._mutable_group(payload, context_key, asset_group)
        group["revealed"] = int(group.get("revealed", 0) or 0) + 1
        pending = payload.setdefault("pending", [])
        if isinstance(pending, list):
            pending.append(
                {
                    "ts": utcnow().isoformat().replace("+00:00", "Z"),
                    "context_key": context_key,
                    "asset_group": asset_group,
                    "binding_id": binding_id,
                    "attacker_key": attacker_key,
                    "asset_id": asset_id,
                    "available_assets": available_assets or [],
                    "revealed_assets": revealed_assets or [asset_id],
                    "status": "pending",
                }
            )
        self._store.write(payload)

    def record_outcome(
        self,
        *,
        context_key: str,
        asset_group: str,
        outcome: str,
    ) -> None:
        """Increment a resolved feedback outcome counter.

        Example:
            Input:
                context_key="T1005", asset_group="finance", outcome="useful"
            Output:
                contexts["T1005"].asset_groups["finance"].useful increments by 1.
        """
        if outcome not in {"useful", "shallow", "ignored"}:
            return
        payload = self._store.read()
        group = self._mutable_group(payload, context_key, asset_group)
        group[outcome] = int(group.get(outcome, 0) or 0) + 1
        self._store.write(payload)

    def _group_record(self, context_key: str, asset_group: str) -> dict[str, Any]:
        """Return one stored feedback bucket without mutating the JSON payload.

        Example:
            Input:
                context_key="T1552.001|path:.bak", asset_group="archive"
            Output:
                {"revealed": 2, "useful": 1} when that bucket exists, otherwise {}.
        """
        payload = self._store.read()
        contexts = payload.get("contexts", {})
        if not isinstance(contexts, dict):
            return {}
        context = contexts.get(context_key, {})
        if not isinstance(context, dict):
            return {}
        groups = context.get("asset_groups", {})
        if not isinstance(groups, dict):
            return {}
        group = groups.get(asset_group, {})
        return group if isinstance(group, dict) else {}

    def _mutable_group(
        self,
        payload: dict[str, Any],
        context_key: str,
        asset_group: str,
    ) -> dict[str, Any]:
        """Return a writable feedback bucket, creating parent objects as needed.

        This method is used only while updating a payload that will later be
        written back to disk. `mutable_nested_dict` also repairs malformed
        intermediate values so counters can still be recorded safely.

        Example:
            Input:
                payload={"contexts": {}}, context_key="T1005", asset_group="finance"
            Output:
                payload now contains contexts["T1005"].asset_groups["finance"] and
                the returned dict can be mutated by the caller.
        """
        return mutable_nested_dict(payload, ("contexts", context_key, "asset_groups", asset_group))


class NoopRevealFeedbackRepository:
    """Fallback feedback repository used when persistence is not configured."""

    def coverage_gap(self, context_key: str, asset_group: str) -> float:
        return 1.0

    def preference(self, context_key: str, asset_group: str) -> float:
        return 0.5

    def record_reveal(
        self,
        *,
        context_key: str,
        asset_group: str,
        binding_id: str,
        attacker_key: str,
        asset_id: str,
        available_assets: list[str] | None = None,
        revealed_assets: list[str] | None = None,
    ) -> None:
        return None

    def record_outcome(
        self,
        *,
        context_key: str,
        asset_group: str,
        outcome: str,
    ) -> None:
        return None
