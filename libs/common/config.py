from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuntimeConfig:
    """Small runtime knobs shared by the MVP services."""

    tick_seconds: int = 30
    epsilon: float = 0.15
    unlock_cap: int = 6
    chain_window_seconds: int = 600
    level2_threshold: int = 3
    binding_ttl_seconds: int = 7 * 24 * 60 * 60
