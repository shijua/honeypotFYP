#!/usr/bin/env python3
"""Build a data-driven ATT&CK hypothesis model from Enterprise ATT&CK STIX.

The model clusters intrusion sets by their ATT&CK technique sets, then turns
each cluster into a Bernoulli technique likelihood table for sequential
Bayesian updates at controller runtime.
"""

from __future__ import annotations

import argparse
from itertools import combinations
import json
import math
from pathlib import Path
from typing import Any


DEFAULT_ALPHA = 1.0
DEFAULT_K_CANDIDATES = (3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 20, 25, 30)
TOP_TECHNIQUE_COUNT = 10
METRICS = ("cosine", "jaccard")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an ATT&CK hypothesis model from Enterprise ATT&CK STIX.",
    )
    parser.add_argument(
        "--stix",
        type=Path,
        default=Path("data/mitre/enterprise-attack.json"),
        help="Local Enterprise ATT&CK STIX bundle.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/technique_prior/attack_hypothesis_model.json"),
        help="Output JSON path for the derived hypothesis model.",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=DEFAULT_ALPHA,
        help="Laplace smoothing parameter for P(technique | hypothesis).",
    )
    parser.add_argument(
        "--metric",
        choices=("auto", *METRICS),
        default="auto",
        help="Distance metric for binary technique sets. auto tries cosine and Jaccard.",
    )
    parser.add_argument(
        "--technique-filter",
        choices=("all", "catalog-covered"),
        default="catalog-covered",
        help="Use all ATT&CK techniques or only technique families covered by the asset catalog.",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("data/assets/catalog.json"),
        help="Asset catalog used when --technique-filter=catalog-covered.",
    )
    args = parser.parse_args()

    model = build_attack_hypothesis_model(
        args.stix,
        alpha=args.alpha,
        metric=args.metric,
        technique_filter=args.technique_filter,
        catalog_path=args.catalog,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(model, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote ATT&CK hypothesis model to {args.output}")
    print(
        f"groups={model['group_count']} techniques={model['technique_count']} "
        f"selected_metric={model['selected_metric']} selected_k={model['selected_k']} "
        f"silhouette={model['selected_silhouette_score']}"
    )
    return 0


def build_attack_hypothesis_model(
    stix_path: Path,
    *,
    alpha: float = DEFAULT_ALPHA,
    k_candidates: tuple[int, ...] = DEFAULT_K_CANDIDATES,
    metric: str = "auto",
    technique_filter: str = "all",
    catalog_path: Path = Path("data/assets/catalog.json"),
) -> dict[str, Any]:
    """Return a serializable hypothesis model from one STIX bundle.

    Example:
        two intrusion sets with overlapping techniques become clustered
        hypotheses with per-technique likelihoods.
    """
    raw_groups = _attack_group_technique_sets(stix_path)
    catalog_techniques = _catalog_covered_techniques(catalog_path) if technique_filter == "catalog-covered" else set()
    groups = _filter_groups_to_techniques(raw_groups, catalog_techniques) if catalog_techniques else raw_groups
    if not groups:
        raise ValueError(f"{stix_path} does not contain active ATT&CK groups with techniques")
    all_techniques = sorted({technique for group in groups for technique in group["techniques"]})
    valid_k = tuple(k for k in k_candidates if 1 < k <= len(groups))
    if not valid_k:
        valid_k = (1,)

    metrics = METRICS if metric == "auto" else (metric,)
    candidates = []
    for metric_name in metrics:
        distances = _pairwise_distances(groups, metric=metric_name)
        for k in valid_k:
            clusters = _agglomerative_clusters(groups, distances, k)
            score = _silhouette_score(clusters, distances) if k > 1 else 0.0
            candidates.append((score, metric_name, k, clusters))
    candidates.sort(key=lambda item: (-item[0], _metric_rank(item[1]), item[2]))
    selected_score, selected_metric, selected_k, selected_clusters = candidates[0]

    hypotheses = [
        _cluster_hypothesis(
            index=index,
            cluster=cluster,
            groups=groups,
            all_techniques=all_techniques,
            alpha=alpha,
        )
        for index, cluster in enumerate(selected_clusters, start=1)
    ]
    return {
        "schema_version": "v1",
        "source": str(stix_path),
        "method": "attack_group_hypothesis_testing",
        "alpha": alpha,
        "metric": metric,
        "selected_metric": selected_metric,
        "technique_filter": technique_filter,
        "catalog": str(catalog_path) if technique_filter == "catalog-covered" else None,
        "k_candidates": list(k_candidates),
        "selected_k": selected_k,
        "selected_silhouette_score": round(selected_score, 6),
        "group_count": len(groups),
        "technique_count": len(all_techniques),
        "hypotheses": hypotheses,
        "silhouette_report": [
            {"metric": metric_name, "k": k, "score": round(score, 6)}
            for score, metric_name, k, _clusters in sorted(candidates, key=lambda item: (item[1], item[2]))
        ],
        "build_report": {
            "top_technique_count": TOP_TECHNIQUE_COUNT,
            "active_groups_with_techniques": len(raw_groups),
            "active_groups_after_filter": len(groups),
            "dropped_groups_after_filter": len(raw_groups) - len(groups),
            "catalog_covered_technique_family_count": len(catalog_techniques),
        },
    }


def _attack_group_technique_sets(stix_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(stix_path.read_text(encoding="utf-8"))
    objects = payload.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError(f"{stix_path} does not contain a STIX objects list")

    groups_by_id = {
        str(item["id"]): item
        for item in objects
        if _is_active_type(item, "intrusion-set") and isinstance(item.get("id"), str)
    }
    techniques_by_id = {
        str(item["id"]): _attack_technique_id(item)
        for item in objects
        if _is_active_type(item, "attack-pattern") and isinstance(item.get("id"), str)
    }
    techniques_by_id = {
        stix_id: technique_id
        for stix_id, technique_id in techniques_by_id.items()
        if technique_id is not None
    }
    techniques_by_group: dict[str, set[str]] = {group_id: set() for group_id in groups_by_id}
    for item in objects:
        if not _is_active_type(item, "relationship") or item.get("relationship_type") != "uses":
            continue
        source_ref = item.get("source_ref")
        target_ref = item.get("target_ref")
        if not isinstance(source_ref, str) or not isinstance(target_ref, str):
            continue
        if source_ref in groups_by_id and target_ref in techniques_by_id:
            techniques_by_group[source_ref].add(techniques_by_id[target_ref])
    groups = [
        {
            "group_id": group_id,
            "name": str(groups_by_id[group_id].get("name", group_id)),
            "techniques": sorted(techniques),
        }
        for group_id, techniques in techniques_by_group.items()
        if techniques
    ]
    groups.sort(key=lambda item: (item["name"], item["group_id"]))
    return groups


def _catalog_covered_techniques(catalog_path: Path) -> set[str]:
    """Return technique families covered by base assets and configuration variants."""
    try:
        assets = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(assets, list):
        return set()
    techniques: set[str] = set()
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        default_settings = asset.get("default_settings")
        if not isinstance(default_settings, dict):
            continue
        selection_profile = default_settings.get("selection_profile")
        if isinstance(selection_profile, dict):
            techniques.update(_technique_families(selection_profile.get("covered_techniques")))
        variants = default_settings.get("configuration_variants")
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict):
                    techniques.update(_technique_families(variant.get("covered_techniques")))
    return techniques


def _filter_groups_to_techniques(
    groups: list[dict[str, Any]],
    allowed_technique_families: set[str],
) -> list[dict[str, Any]]:
    """Limit each ATT&CK group to technique families the catalog can act on."""
    filtered_groups = []
    for group in groups:
        techniques = [
            technique
            for technique in group["techniques"]
            if _technique_family(technique) in allowed_technique_families
        ]
        if techniques:
            filtered_groups.append({**group, "techniques": sorted(set(techniques))})
    return filtered_groups


def _technique_families(raw_techniques: object) -> set[str]:
    if not isinstance(raw_techniques, list):
        return set()
    return {
        _technique_family(technique)
        for technique in raw_techniques
        if isinstance(technique, str) and technique.startswith("T")
    }


def _technique_family(technique: str) -> str:
    return technique.split(".", 1)[0]


def _pairwise_distances(groups: list[dict[str, Any]], *, metric: str) -> dict[tuple[int, int], float]:
    distances: dict[tuple[int, int], float] = {}
    for left, right in combinations(range(len(groups)), 2):
        left_techniques = set(groups[left]["techniques"])
        right_techniques = set(groups[right]["techniques"])
        distances[(left, right)] = _technique_set_distance(left_techniques, right_techniques, metric)
    return distances


def _technique_set_distance(left: set[str], right: set[str], metric: str) -> float:
    if metric == "jaccard":
        return _jaccard_distance(left, right)
    if metric == "cosine":
        return _cosine_distance(left, right)
    raise ValueError(f"unsupported metric: {metric}")


def _cosine_distance(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 1.0
    similarity = len(left & right) / math.sqrt(len(left) * len(right))
    return max(0.0, min(1.0, 1.0 - similarity))


def _jaccard_distance(left: set[str], right: set[str]) -> float:
    union = left | right
    if not union:
        return 1.0
    similarity = len(left & right) / len(union)
    return max(0.0, min(1.0, 1.0 - similarity))


def _metric_rank(metric: str) -> int:
    return 0 if metric == "jaccard" else 1


def _agglomerative_clusters(
    groups: list[dict[str, Any]],
    distances: dict[tuple[int, int], float],
    target_k: int,
) -> list[list[int]]:
    clusters = [[index] for index in range(len(groups))]
    while len(clusters) > target_k:
        best_pair: tuple[int, int] | None = None
        best_distance = float("inf")
        for left_index, right_index in combinations(range(len(clusters)), 2):
            distance = _average_cluster_distance(
                clusters[left_index],
                clusters[right_index],
                distances,
            )
            if distance < best_distance:
                best_pair = (left_index, right_index)
                best_distance = distance
        if best_pair is None:
            break
        left_index, right_index = best_pair
        clusters[left_index] = sorted([*clusters[left_index], *clusters[right_index]])
        del clusters[right_index]
    clusters.sort(key=lambda cluster: (len(cluster), cluster[0]), reverse=True)
    return clusters


def _average_cluster_distance(
    left_cluster: list[int],
    right_cluster: list[int],
    distances: dict[tuple[int, int], float],
) -> float:
    values = [
        _distance_between(left, right, distances)
        for left in left_cluster
        for right in right_cluster
    ]
    return sum(values) / len(values) if values else 0.0


def _distance_between(left: int, right: int, distances: dict[tuple[int, int], float]) -> float:
    if left == right:
        return 0.0
    return distances[(left, right)] if left < right else distances[(right, left)]


def _silhouette_score(
    clusters: list[list[int]],
    distances: dict[tuple[int, int], float],
) -> float:
    sample_scores: list[float] = []
    for cluster in clusters:
        for sample in cluster:
            own_neighbors = [item for item in cluster if item != sample]
            a_score = (
                sum(_distance_between(sample, item, distances) for item in own_neighbors)
                / len(own_neighbors)
                if own_neighbors
                else 0.0
            )
            other_scores = [
                sum(_distance_between(sample, item, distances) for item in other_cluster)
                / len(other_cluster)
                for other_cluster in clusters
                if other_cluster is not cluster and other_cluster
            ]
            b_score = min(other_scores) if other_scores else 0.0
            denominator = max(a_score, b_score)
            sample_scores.append((b_score - a_score) / denominator if denominator else 0.0)
    return sum(sample_scores) / len(sample_scores) if sample_scores else 0.0


def _cluster_hypothesis(
    *,
    index: int,
    cluster: list[int],
    groups: list[dict[str, Any]],
    all_techniques: list[str],
    alpha: float,
) -> dict[str, Any]:
    group_refs = [groups[index_] for index_ in cluster]
    group_count = len(group_refs)
    support_counts = {
        technique: sum(1 for group in group_refs if technique in group["techniques"])
        for technique in all_techniques
    }
    likelihoods = {
        technique: round((count + alpha) / (group_count + 2 * alpha), 6)
        for technique, count in support_counts.items()
    }
    top_techniques = [
        {
            "technique": technique,
            "likelihood": likelihoods[technique],
            "support_count": support_counts[technique],
        }
        for technique in sorted(
            all_techniques,
            key=lambda item: (-likelihoods[item], -support_counts[item], item),
        )[:TOP_TECHNIQUE_COUNT]
    ]
    return {
        "hypothesis_id": f"hypothesis-{index}",
        "label": f"hypothesis-{index}",
        "group_count": group_count,
        "groups": [
            {"group_id": group["group_id"], "name": group["name"]}
            for group in group_refs
        ],
        "top_techniques": top_techniques,
        "likelihoods": likelihoods,
    }


def _is_active_type(item: object, expected_type: str) -> bool:
    if not isinstance(item, dict) or item.get("type") != expected_type:
        return False
    return not bool(item.get("revoked")) and not bool(item.get("x_mitre_deprecated"))


def _attack_technique_id(item: dict[str, Any]) -> str | None:
    refs = item.get("external_references")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        external_id = ref.get("external_id")
        if ref.get("source_name") == "mitre-attack" and isinstance(external_id, str):
            if external_id.startswith("T"):
                return external_id
    return None


if __name__ == "__main__":
    raise SystemExit(main())
