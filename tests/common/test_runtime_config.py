from __future__ import annotations

import pytest

from libs.common.config import RuntimeConfig


pytestmark = pytest.mark.unit


def test_runtime_config_reads_cowrie_mapping_mode_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HONEYPOT_COWRIE_COMMAND_MAPPING_MODE", "hybrid")
    monkeypatch.setenv(
        "HONEYPOT_COWRIE_SIGMA_RULES_PATH",
        "vendor/custom-sigma/rules/linux",
    )
    monkeypatch.setenv(
        "HONEYPOT_ENTRYPOINT_HTTP_SIGMA_RULES_PATH",
        "vendor/custom-sigma/rules/web",
    )

    config = RuntimeConfig.from_env()

    assert config.cowrie_command_mapping_mode == "hybrid"
    assert config.cowrie_sigma_rules_path == "vendor/custom-sigma/rules/linux"
    assert config.entrypoint_http_sigma_rules_path == "vendor/custom-sigma/rules/web"


def test_runtime_config_reads_prior_and_feedback_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HONEYPOT_ATTACK_GROUP_PRIOR_PATH", "tmp/group_prior.json")
    monkeypatch.setenv("HONEYPOT_RECOMMENDATION_TOP_K", "40")
    monkeypatch.setenv("HONEYPOT_RECOMMENDATION_SUPPORT_THRESHOLD", "0.15")
    monkeypatch.setenv("HONEYPOT_OBSERVED_TECHNIQUE_THRESHOLD", "0.5")
    monkeypatch.setenv("HONEYPOT_FEEDBACK_WINDOW_SECONDS", "120")
    monkeypatch.setenv("HONEYPOT_REVEAL_FEEDBACK_PATH", "tmp/reveal_feedback.json")

    config = RuntimeConfig.from_env()

    assert config.attack_group_prior_path == "tmp/group_prior.json"
    assert config.recommendation_top_k == 40
    assert config.recommendation_support_threshold == 0.15
    assert config.observed_technique_threshold == 0.5
    assert config.feedback_window_seconds == 120
    assert config.reveal_feedback_path == "tmp/reveal_feedback.json"
