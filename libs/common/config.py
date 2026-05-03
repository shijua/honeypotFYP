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
        """Build config from repo defaults plus supported environment overrides."""
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
        return config
