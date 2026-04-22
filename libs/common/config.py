"""Shared runtime configuration used by the MVP services.

Most values here are intentionally simple constants so local runs and tests can
share the same defaults.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuntimeConfig:
    """Small runtime knobs shared by the MVP services.

    Example:
        RuntimeConfig(epsilon=0.15, asset_catalog_path="data/assets/catalog.json")
    """

    tick_seconds: int = 30
    epsilon: float = 0.15
    unlock_cap: int = 6
    chain_window_seconds: int = 600
    level2_threshold: int = 3
    binding_ttl_seconds: int = 7 * 24 * 60 * 60
    state_dir: str = "data/runtime"
    generated_template_dir: str = "data/runtime/generated_templates"
    asset_catalog_path: str = "data/assets/catalog.json"
    cowrie_event_mapping_path: str = "data/cowrie/event_mappings.json"
    cowrie_command_mapping_path: str = "data/cowrie/command_mapping_rules.json"
    entrypoint_body_preview_bytes: int = 2048
    mitre_attack_stix_path: str = "data/mitre/enterprise-attack.json"
    mitre_attack_stix_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )
