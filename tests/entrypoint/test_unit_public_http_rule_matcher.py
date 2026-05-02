from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.entrypoint.rule_matcher import FilePublicHttpRuleMatcher


pytestmark = pytest.mark.unit


def test_public_http_rule_matcher_maps_secret_and_scanner_probes() -> None:
    matcher = FilePublicHttpRuleMatcher("data/detections/public_http_rules.json")

    assert matcher.tags_for(method="GET", path="/.env.old") == [
        "mitre_credential_access",
        "T1552.001",
    ]
    assert matcher.tags_for(
        method="GET",
        path="/assets/app.js.map",
        user_agent="gobuster/3.6",
    ) == ["mitre_discovery", "T1046"]
    matches = matcher.matches_for(
        method="GET",
        path="/assets/app.js.map",
        user_agent="sqlmap/1.8",
    )
    assert matches[0].rule_name == "public_http_web_discovery"
    assert matches[0].evidence_label == "public-http scanner or web discovery probe"
    assert "user_agent:sqlmap" in matches[0].indicators
    assert "path:.map" in matches[0].indicators
    injection_matches = matcher.matches_for(
        method="GET",
        path="/api/search",
        query_string="q=1%20union%20select%201",
        user_agent="sqlmap/1.8",
    )
    assert [match.rule_name for match in injection_matches] == [
        "public_http_injection_probe",
        "public_http_web_discovery",
    ]
    assert "combined:union%20select" in injection_matches[0].indicators
    assert injection_matches[0].tags == ("mitre_initial_access", "T1190")


def test_public_http_rule_matcher_maps_internal_artifact_access() -> None:
    matcher = FilePublicHttpRuleMatcher("data/detections/public_http_rules.json")

    matches = matcher.matches_for(
        method="GET",
        path="/downloads/agent-update.bin",
        surface="internal",
        asset_id="malware-sink",
    )

    assert [match.rule_name for match in matches] == [
        "internal_http_artifact_access"
    ]
    assert matches[0].tags == ("mitre_collection", "T1005")
    assert "surface:internal" in matches[0].indicators
    assert "path:/downloads/" in matches[0].indicators
    assert "path:.bin" in matches[0].indicators


def test_public_http_rule_matcher_supports_json_rule_files(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        json.dumps(
            {
                "schema_version": "v1",
                "rules": [
                    {
                        "name": "custom_post_login",
                        "evidence_label": "custom login evidence",
                        "tags": ["mitre_credential_access", "T1110"],
                        "match": {
                            "all": [
                                {"field": "method", "equals_any": ["POST"]},
                                {"field": "body_preview", "contains_any": ["pwd="]},
                            ]
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    matcher = FilePublicHttpRuleMatcher(rules_path)

    assert matcher.tags_for(method="POST", path="/", body_preview="user=a&pwd=x") == [
        "mitre_credential_access",
        "T1110",
    ]
    matches = matcher.matches_for(method="POST", path="/", body_preview="user=a&pwd=x")
    assert matches[0].evidence_label == "custom login evidence"
    assert matches[0].indicators == ("method:POST", "body_preview:pwd=")
    assert matcher.tags_for(method="GET", path="/", body_preview="user=a&pwd=x") == []
