"""Repository adapters for controller inputs.

The controller consumes two durable inputs:
- the asset catalog it may expose
- a public ATT&CK group-technique prior used for technique recommendation
"""

from __future__ import annotations

from collections.abc import Iterable
import json
from pathlib import Path
from typing import Any, Protocol

from libs.common.clock import utcnow
from libs.common.json_store import JsonFileStore
from libs.contracts.models import AssetDefinition


class AssetRepository(Protocol):
    """Storage contract for the controller asset catalog.

    Example:
        list_all() -> [AssetDefinition(asset_id="internal-portal", ...)]
    """

    def list_all(self) -> Iterable[AssetDefinition]:
        """Return the template catalog available to the controller."""
        ...


class TechniquePriorRepository(Protocol):
    """Lookup contract for ATT&CK group technique recommendations.

    Example:
        recommend({"T1190", "T1033"}, top_k=5, support_threshold=0.15)
        -> {"T1059": 0.4, "T1105": 0.22}
    """

    @property
    def degraded_reason(self) -> str | None:
        """Return why the prior is unavailable, or None when healthy."""
        ...

    def recommend(
        self,
        observed_techniques: set[str],
        *,
        top_k: int,
        support_threshold: float,
    ) -> dict[str, float]:
        """Return supported not-yet-observed techniques from the top-k similar groups."""
        ...


class FileAssetRepository:
    """JSON-backed asset catalog used by the default controller runtime."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def list_all(self) -> Iterable[AssetDefinition]:
        with self._path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return tuple(AssetDefinition.model_validate(item) for item in payload)


class FileAttackGroupTechniquePriorRepository:
    """File-backed collaborative-filtering technique prior.

    Input file shape:
        {
          "groups": [
            {"group_id": "intrusion-set--1", "name": "Example", "techniques": ["T1190", "T1059"]}
          ]
        }

    Example:
        recommend({"T1190"}, top_k=3, support_threshold=0.1) -> {"T1059": 0.666667}
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._groups: list[dict[str, Any]] = []
        self._degraded_reason: str | None = None
        self._load()

    @property
    def degraded_reason(self) -> str | None:
        return self._degraded_reason

    def recommend(
        self,
        observed_techniques: set[str],
        *,
        top_k: int,
        support_threshold: float,
    ) -> dict[str, float]:
        """Return weighted kNN recommendations from ATT&CK group context.

        The implementation uses Sørensen-Dice similarity between the current
        binding's thresholded observed techniques and each ATT&CK group technique set.
        It follows the ATT&CK behavior forecasting paper's WkNN rule:
        each top-k similar group contributes 1 / (1 - similarity), then support
        is divided by k. K is the number of neighboring groups, not a cap on the
        number of recommended techniques. Exact-match groups add no unseen
        techniques, so they do not need a distance weight.

        Example:
            observed={"T1190"}, group techniques={"T1190", "T1059"}
            -> similarity=0.666667, weight=3, support=3/top_k.
        """
        observed = {item for item in observed_techniques if item}
        if not observed or not self._groups:
            return {}

        similar_groups = [
            (score, group)
            for group in self._groups
            if (score := _dice_similarity(observed, set(group.get("techniques", [])))) > 0
        ]
        similar_groups.sort(
            key=lambda item: (-item[0], str(item[1].get("name", "")))
        )
        neighbors = similar_groups[: max(1, top_k)]

        candidate_scores: dict[str, float] = {}
        for similarity, group in neighbors:
            weight = _wknn_weight(similarity)
            if weight <= 0:
                continue
            for technique in group.get("techniques", []):
                if not isinstance(technique, str) or technique in observed:
                    continue
                candidate_scores[technique] = candidate_scores.get(technique, 0.0) + weight

        denominator = max(1, top_k)
        normalized = {
            technique: round(score / denominator, 6)
            for technique, score in candidate_scores.items()
            if (score / denominator) >= support_threshold
        }
        return dict(
            sorted(normalized.items(), key=lambda item: (-item[1], item[0]))
        )

    def _load(self) -> None:
        if not self._path.exists():
            self._groups = []
            self._degraded_reason = f"attack group prior file missing: {self._path}"
            return
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._groups = []
            self._degraded_reason = f"could not load attack group prior {self._path}: {exc}"
            return
        groups = payload.get("groups") if isinstance(payload, dict) else None
        if not isinstance(groups, list):
            self._groups = []
            self._degraded_reason = f"attack group prior has no groups list: {self._path}"
            return
        self._groups = [
            {
                "group_id": str(group.get("group_id", "")),
                "name": str(group.get("name", "")),
                "techniques": sorted(
                    {
                        technique
                        for technique in group.get("techniques", [])
                        if isinstance(technique, str) and technique
                    }
                ),
            }
            for group in groups
            if isinstance(group, dict)
        ]
        self._degraded_reason = None if self._groups else "attack group prior has no usable groups"


def _dice_similarity(left: set[str], right: set[str]) -> float:
    """Return Sørensen-Dice similarity for two technique sets.

    Example:
        left={"T1190", "T1033"}, right={"T1190", "T1059"} -> 0.5
    """
    if not left or not right:
        return 0.0
    return (2 * len(left & right)) / (len(left) + len(right))


def _wknn_weight(similarity: float) -> float:
    """Return the paper's WkNN distance weight for one similar group.

    Example:
        similarity=0.5 -> distance=0.5 -> weight=2.0.
    """
    if similarity <= 0:
        return 0.0
    distance = 1 - similarity
    if distance <= 0:
        return 0.0
    return 1 / distance


class FileRevealFeedbackRepository:
    """File-backed store for reveal follow-up outcomes.

    The controller does not read this store for ranking. The adaptive loop uses
    it as runtime feedback state: which asset was revealed, whether later
    evidence made that reveal useful/shallow/ignored, and whether a binding is
    allowed to reveal another asset.

    Example:
        record_reveal(asset_id="finance-share", context_key="T1005|path:.bak", ...)
        appends one pending reveal to `data/runtime/reveal_feedback.json`.
    """

    def __init__(self, path: str | Path) -> None:
        self._store = JsonFileStore(path, default_data={"schema_version": "v1", "contexts": {}, "pending": []})

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
        """Record one reveal that later evidence may resolve.

        Example:
            Input:
                asset_id="finance-share", available_assets=["finance-share", "git-internal"]
            Output:
                pending contains one finance-share reveal for the attacker/binding.
        """
        group_path = ("contexts", context_key, "asset_groups", asset_group)
        self._store.increment_nested_int(group_path, "revealed")
        self._store.append_to_list(
            "pending",
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
            },
        )

    def record_outcome(
        self,
        *,
        context_key: str,
        asset_group: str,
        outcome: str,
    ) -> None:
        """Increment one resolved feedback counter.

        Example:
            record_outcome(context_key="T1005", asset_group="finance", outcome="useful")
            increments `contexts.T1005.asset_groups.finance.useful`.
        """
        if outcome not in {"useful", "shallow", "ignored"}:
            return
        group_path = ("contexts", context_key, "asset_groups", asset_group)
        self._store.increment_nested_int(group_path, outcome)
