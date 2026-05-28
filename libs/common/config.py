"""Shared runtime configuration used by the honeynet services.

Most values here are intentionally simple constants so local runs and tests can
share the same defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass
class RuntimeConfig:
    """Small runtime knobs shared by the honeynet services.

    Example:
        RuntimeConfig(asset_catalog_path="data/assets/catalog.json", unlock_cap=2)
    """

    tick_seconds: int = 30
    unlock_cap: int = 100
    chain_window_seconds: int = 600
    binding_ttl_seconds: int = 7 * 24 * 60 * 60
    state_dir: str = "data/runtime"
    asset_catalog_path: str = "data/assets/catalog.json"
    attack_group_prior_path: str = "data/technique_prior/attack_group_technique_prior.json"
    attack_hypothesis_model_path: str = "data/technique_prior/attack_hypothesis_model.json"
    controller_policy_mode: str = "cf-gated"
    recommendation_top_k: int = 40
    recommendation_support_threshold: float = 0.15
    strong_technique_threshold: float = 0.5
    hypothesis_convergence_threshold: float = 0.8
    hypothesis_min_discriminative_score: float = 0.05
    feedback_window_seconds: int = 300
    reveal_feedback_path: str = "data/runtime/reveal_feedback.json"
    cowrie_event_mapping_path: str = "data/cowrie/event_mappings.json"
    cowrie_command_mapping_mode: str = "hybrid"
    cowrie_command_mapping_path: str = "data/cowrie/command_mapping_rules.json"
    cowrie_sigma_rules_path: str = "data/detections/cowrie_sigma:vendor/sigma/rules/linux"
    entrypoint_http_sigma_rules_path: str = "data/detections/http_sigma"
    entrypoint_body_preview_bytes: int = 2048
    mitre_attack_stix_path: str = "data/mitre/enterprise-attack.json"
    mitre_attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    @classmethod
    def from_env(cls) -> "RuntimeConfig":
        """Build config from repo defaults plus supported environment overrides.

        Example:
            Input env:
                HONEYPOT_ATTACK_GROUP_PRIOR_PATH=tmp/group_prior.json
                HONEYPOT_RECOMMENDATION_TOP_K=40
                HONEYPOT_RECOMMENDATION_SUPPORT_THRESHOLD=0.15
                HONEYPOT_STRONG_TECHNIQUE_THRESHOLD=0.5
            Output:
                config.attack_group_prior_path == "tmp/group_prior.json"
                config.recommendation_top_k == 40
                config.recommendation_support_threshold == 0.15
                config.strong_technique_threshold == 0.5
        """
        config = cls()
        config.state_dir = os.getenv("HONEYPOT_STATE_DIR", config.state_dir)
        config.cowrie_command_mapping_mode = os.getenv(
            "HONEYPOT_COWRIE_COMMAND_MAPPING_MODE",
            config.cowrie_command_mapping_mode,
        )
        config.cowrie_command_mapping_path = os.getenv(
            "HONEYPOT_COWRIE_COMMAND_MAPPING_PATH",
            config.cowrie_command_mapping_path,
        )
        config.cowrie_sigma_rules_path = os.getenv(
            "HONEYPOT_COWRIE_SIGMA_RULES_PATH",
            config.cowrie_sigma_rules_path,
        )
        config.entrypoint_http_sigma_rules_path = os.getenv(
            "HONEYPOT_ENTRYPOINT_HTTP_SIGMA_RULES_PATH",
            config.entrypoint_http_sigma_rules_path,
        )
        config.attack_group_prior_path = os.getenv(
            "HONEYPOT_ATTACK_GROUP_PRIOR_PATH",
            config.attack_group_prior_path,
        )
        config.attack_hypothesis_model_path = os.getenv(
            "HONEYPOT_ATTACK_HYPOTHESIS_MODEL_PATH",
            config.attack_hypothesis_model_path,
        )
        config.controller_policy_mode = os.getenv(
            "HONEYPOT_CONTROLLER_POLICY_MODE",
            config.controller_policy_mode,
        )
        config.recommendation_top_k = _env_int(
            "HONEYPOT_RECOMMENDATION_TOP_K",
            config.recommendation_top_k,
        )
        config.recommendation_support_threshold = _env_float(
            "HONEYPOT_RECOMMENDATION_SUPPORT_THRESHOLD",
            config.recommendation_support_threshold,
        )
        config.strong_technique_threshold = _env_float(
            "HONEYPOT_STRONG_TECHNIQUE_THRESHOLD",
            config.strong_technique_threshold,
        )
        config.hypothesis_convergence_threshold = _env_float(
            "HONEYPOT_HYPOTHESIS_CONVERGENCE_THRESHOLD",
            config.hypothesis_convergence_threshold,
        )
        config.hypothesis_min_discriminative_score = _env_float(
            "HONEYPOT_HYPOTHESIS_MIN_DISCRIMINATIVE_SCORE",
            config.hypothesis_min_discriminative_score,
        )
        config.feedback_window_seconds = _env_int(
            "HONEYPOT_FEEDBACK_WINDOW_SECONDS",
            config.feedback_window_seconds,
        )
        config.reveal_feedback_path = os.getenv(
            "HONEYPOT_REVEAL_FEEDBACK_PATH",
            config.reveal_feedback_path,
        )
        return config


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable with a safe fallback.

    Example:
        Input:
            name="HONEYPOT_RECOMMENDATION_TOP_K", default=40, env value="12"
        Output:
            12
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    """Read a floating-point environment variable with a safe fallback.

    Example:
        Input:
            name="HONEYPOT_RECOMMENDATION_SUPPORT_THRESHOLD", default=0.15, env value="0.25"
        Output:
            0.25
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default
