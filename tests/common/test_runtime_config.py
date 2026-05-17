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


def test_runtime_config_reads_transition_and_feedback_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HONEYPOT_ATTACK_TRANSITION_PRIOR_PATH", "tmp/prior.json")
    monkeypatch.setenv("HONEYPOT_TRANSITION_TOP_K", "7")
    monkeypatch.setenv("HONEYPOT_TRANSITION_MIN_SUPPORT", "3")
    monkeypatch.setenv("HONEYPOT_TRANSITION_ORDER2_MIN_SUPPORT", "4")
    monkeypatch.setenv("HONEYPOT_TRANSITION_ORDER3_MIN_SUPPORT", "5")
    monkeypatch.setenv("HONEYPOT_EXPLOIT_LAMBDA", "0.75")
    monkeypatch.setenv("HONEYPOT_FEEDBACK_WINDOW_SECONDS", "120")
    monkeypatch.setenv("HONEYPOT_REVEAL_FEEDBACK_PATH", "tmp/reveal_feedback.json")

    config = RuntimeConfig.from_env()

    assert config.attack_transition_prior_path == "tmp/prior.json"
    assert config.transition_top_k == 7
    assert config.transition_min_support == 3
    assert config.transition_order2_min_support == 4
    assert config.transition_order3_min_support == 5
    assert config.exploit_lambda == 0.75
    assert config.feedback_window_seconds == 120
    assert config.reveal_feedback_path == "tmp/reveal_feedback.json"
