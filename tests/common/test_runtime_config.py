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
