from __future__ import annotations

from pathlib import Path

from services.profiler.attack_catalog import MitreAttackCatalog


def build_test_attack_catalog() -> MitreAttackCatalog:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "mitre_attack_enterprise_mini.json"
    )
    return MitreAttackCatalog(fixture_path)
