"""Shared runtime configuration used by the MVP services.

Most values here are intentionally simple constants so local runs and tests can
share the same defaults.
"""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass
class RuntimeConfig:
    """Small runtime knobs shared by the MVP services.

    Example:
        RuntimeConfig(epsilon=0.15, asset_catalog_path="data/assets/catalog.json")
    """

    tick_seconds: int = 30
    epsilon: float = 0.15
    unlock_cap: int = 100
    chain_window_seconds: int = 600
    level2_threshold: int = 3
    binding_ttl_seconds: int = 7 * 24 * 60 * 60
    state_dir: str = "data/runtime"
    asset_catalog_path: str = "data/assets/catalog.json"
    attack_transition_prior_path: str = "data/transitions/technique_transition_prior.json"
    transition_top_k: int = 5
    transition_min_support: int = 1
    transition_order2_min_support: int = 2
    transition_order3_min_support: int = 3
    exploit_lambda: float = 0.6
    feedback_window_seconds: int = 300
    reveal_feedback_path: str = "data/runtime/reveal_feedback.json"
    cowrie_event_mapping_path: str = "data/cowrie/event_mappings.json"
    cowrie_command_mapping_mode: str = "sigma"
    cowrie_command_mapping_path: str = "data/cowrie/command_mapping_rules.json"
    cowrie_sigma_rules_path: str = "vendor/sigma/rules/linux"
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
                HONEYPOT_TRANSITION_TOP_K=7
                HONEYPOT_TRANSITION_ORDER2_MIN_SUPPORT=2
                HONEYPOT_TRANSITION_ORDER3_MIN_SUPPORT=3
                HONEYPOT_ATTACK_TRANSITION_PRIOR_PATH=tmp/prior.json
            Output:
                config.transition_top_k == 7
                config.transition_order2_min_support == 2
                config.transition_order3_min_support == 3
                config.attack_transition_prior_path == "tmp/prior.json"
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
        config.attack_transition_prior_path = os.getenv(
            "HONEYPOT_ATTACK_TRANSITION_PRIOR_PATH",
            config.attack_transition_prior_path,
        )
        config.transition_top_k = _env_int(
            "HONEYPOT_TRANSITION_TOP_K",
            config.transition_top_k,
        )
        config.transition_min_support = _env_int(
            "HONEYPOT_TRANSITION_MIN_SUPPORT",
            config.transition_min_support,
        )
        config.transition_order2_min_support = _env_int(
            "HONEYPOT_TRANSITION_ORDER2_MIN_SUPPORT",
            config.transition_order2_min_support,
        )
        config.transition_order3_min_support = _env_int(
            "HONEYPOT_TRANSITION_ORDER3_MIN_SUPPORT",
            config.transition_order3_min_support,
        )
        config.exploit_lambda = _env_float(
            "HONEYPOT_EXPLOIT_LAMBDA",
            config.exploit_lambda,
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
            name="HONEYPOT_TRANSITION_TOP_K", default=5, env value="7"
        Output:
            7
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
            name="HONEYPOT_EXPLOIT_LAMBDA", default=0.6, env value="0.75"
        Output:
            0.75
    """
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default
