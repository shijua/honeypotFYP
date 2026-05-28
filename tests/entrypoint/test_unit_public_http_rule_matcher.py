from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from services.entrypoint.rule_matcher import FilePublicHttpRuleMatcher
from services.entrypoint.sigma_mapping import FilePublicHttpSigmaRuleMatcher


pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]
INTERNAL_ASSET_HTML_ROOTS = {
    "finance-share": ROOT / "deploy/internal-assets/finance-share/html",
    "internal-portal": ROOT / "deploy/internal-assets/internal-portal/html",
    "malware-sink": ROOT / "deploy/internal-assets/malware-sink/html",
    "vpn-appliance": ROOT / "deploy/internal-assets/vpn-appliance/html",
    "web-admin-console": ROOT / "deploy/internal-assets/web-admin-console/html",
}


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


def test_public_http_sigma_matcher_maps_secret_and_scanner_probes() -> None:
    matcher = FilePublicHttpSigmaRuleMatcher("data/detections/http_sigma")

    assert matcher.tags_for(method="GET", path="/.env.old") == [
        "mitre_credential_access",
        "T1552.001",
    ]
    matches = matcher.matches_for(
        method="GET",
        path="/assets/app.js.map",
        user_agent="sqlmap/1.8",
    )
    assert [match.rule_name for match in matches] == ["public_http_web_discovery"]
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
        "internal_http_artifact_access",
        "internal_http_package_transfer",
    ]
    assert matches[0].tags == ("mitre_collection", "T1005")
    assert "surface:internal" in matches[0].indicators
    assert "path:/downloads/" in matches[0].indicators
    assert "path:.bin" in matches[0].indicators
    assert matches[1].tags == ("mitre_command_and_control", "T1105")


def test_public_http_sigma_matcher_maps_internal_artifact_access() -> None:
    matcher = FilePublicHttpSigmaRuleMatcher("data/detections/http_sigma")

    matches = matcher.matches_for(
        method="GET",
        path="/finance/archive/2024/payroll-archive.zip",
        surface="internal",
        asset_id="finance-share",
    )

    assert [match.rule_name for match in matches] == ["internal_http_artifact_access"]
    assert matches[0].tags == ("mitre_collection", "T1005")
    assert "surface:internal" in matches[0].indicators
    assert "path:/finance/archive/2024/payroll-archive.zip" in matches[0].indicators


def test_internal_http_sigma_asset_paths_exist() -> None:
    materialized_paths = _configuration_materialized_paths()
    for rule_path in sorted((ROOT / "data/detections/http_sigma").glob("internal_http_*.yml")):
        payload = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        detection = payload.get("detection", {}) if isinstance(payload, dict) else {}
        asset_id = _rule_asset_id(detection)
        if asset_id is None:
            continue
        html_root = INTERNAL_ASSET_HTML_ROOTS.get(asset_id)
        if html_root is None:
            continue
        for path in _rule_paths(detection):
            if _is_configuration_materialized_path(materialized_paths, asset_id, path):
                continue
            assert _asset_path_exists(html_root, path), f"{rule_path} references missing {asset_id}:{path}"


@pytest.mark.parametrize(
    ("path", "asset_id", "expected_rule", "expected_tags"),
    [
        (
            "/api/inventory.json",
            "web-admin-console",
            "internal_http_web_admin_inventory",
            ("mitre_discovery", "T1518"),
        ),
        (
            "/api/groups.json",
            "web-admin-console",
            "internal_http_web_admin_groups",
            ("mitre_discovery", "T1069"),
        ),
        (
            "/api/container-resources.json",
            "web-admin-console",
            "internal_http_web_admin_container_resources",
            ("mitre_discovery", "T1082"),
        ),
        (
            "/staging/manifest.json",
            "malware-sink",
            "internal_http_payload_staging_manifest",
            ("mitre_resource_development", "T1608"),
        ),
        (
            "/staging/archive-plan.txt",
            "malware-sink",
            "internal_http_payload_archive_staging",
            ("mitre_collection", "T1074"),
        ),
        (
            "/downloads/agent-update.bin",
            "malware-sink",
            "internal_http_package_transfer",
            ("mitre_command_and_control", "T1105"),
        ),
    ],
)
def test_public_http_sigma_matcher_keeps_internal_actions_fine_grained(
    path: str,
    asset_id: str,
    expected_rule: str,
    expected_tags: tuple[str, str],
) -> None:
    matcher = FilePublicHttpSigmaRuleMatcher("data/detections/http_sigma")

    matches = matcher.matches_for(
        method="GET",
        path=path,
        surface="internal",
        asset_id=asset_id,
    )

    assert [match.rule_name for match in matches] == [expected_rule]
    assert matches[0].tags == expected_tags


def test_public_http_sigma_matcher_requires_post_for_upload_exfiltration() -> None:
    matcher = FilePublicHttpSigmaRuleMatcher("data/detections/http_sigma")

    assert matcher.matches_for(
        method="GET",
        path="/upload/README.txt",
        surface="internal",
        asset_id="malware-sink",
    ) == []
    matches = matcher.matches_for(
        method="POST",
        path="/upload/",
        body_preview="filename=finance-drop.zip",
        surface="internal",
        asset_id="malware-sink",
    )

    assert [match.rule_name for match in matches] == ["internal_http_payload_exfil_upload"]
    assert matches[0].tags == ("mitre_exfiltration", "T1567")


def test_public_http_rule_matcher_maps_internal_portal_token_reuse() -> None:
    matcher = FilePublicHttpRuleMatcher("data/detections/public_http_rules.json")

    matches = matcher.matches_for(
        method="POST",
        path="/session",
        body_preview="username=portal.reader&token=[redacted]&auth_result=success",
        surface="internal",
        asset_id="internal-portal",
    )

    assert [match.rule_name for match in matches] == [
        "internal_http_login_attempt",
        "internal_http_valid_token_reuse",
    ]
    assert matches[0].tags == ("mitre_credential_access", "T1110")
    assert matches[1].tags == ("mitre_lateral_movement", "T1021")


def test_public_http_sigma_matcher_maps_internal_portal_token_reuse() -> None:
    matcher = FilePublicHttpSigmaRuleMatcher("data/detections/http_sigma")

    matches = matcher.matches_for(
        method="POST",
        path="/session",
        body_preview="username=portal.reader&token=[redacted]&auth_result=success",
        surface="internal",
        asset_id="internal-portal",
    )

    assert [match.rule_name for match in matches] == [
        "internal_http_login_attempt",
        "internal_http_valid_token_reuse",
    ]
    assert matches[0].tags == ("mitre_credential_access", "T1110")
    assert matches[1].tags == (
        "mitre_lateral_movement",
        "T1021",
        "mitre_defense_evasion",
        "T1078",
    )


def test_public_http_sigma_matcher_supports_simple_filters(tmp_path: Path) -> None:
    sigma_file = tmp_path / "filtered_admin.yml"
    sigma_file.write_text(
        """
title: Filtered Admin Probe
honeynet.rule_name: filtered_admin_probe
honeynet.evidence_label: filtered admin probe
detection:
  selection:
    url.path|contains: /admin
  filter_healthcheck:
    http.user_agent|contains: healthcheck
  condition: selection and not filter_healthcheck
tags:
  - attack.discovery
  - attack.t1046
""",
        encoding="utf-8",
    )
    matcher = FilePublicHttpSigmaRuleMatcher(tmp_path)

    assert [match.rule_name for match in matcher.matches_for(method="GET", path="/admin")] == [
        "filtered_admin_probe"
    ]
    assert matcher.matches_for(method="GET", path="/admin", user_agent="healthcheck") == []


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


def _rule_asset_id(detection: dict[str, object]) -> str | None:
    for block in detection.values():
        if not isinstance(block, dict):
            continue
        value = block.get("honeynet.asset_id") or block.get("asset_id")
        if isinstance(value, str):
            return value
    return None


def _rule_paths(detection: dict[str, object]) -> list[str]:
    paths: list[str] = []
    for block in detection.values():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if "url.path" not in str(key):
                continue
            values = value if isinstance(value, list) else [value]
            paths.extend(item for item in values if isinstance(item, str) and item.startswith("/"))
    return paths


def _asset_path_exists(html_root: Path, path: str) -> bool:
    relative = path.lstrip("/")
    candidate = html_root / relative
    if candidate.exists():
        return True
    return any(str(existing.relative_to(html_root)).startswith(relative) for existing in html_root.rglob("*"))


def _configuration_materialized_paths() -> dict[str, set[str]]:
    catalog = json.loads((ROOT / "data/assets/catalog.json").read_text(encoding="utf-8"))
    paths_by_asset: dict[str, set[str]] = {}
    for asset in catalog:
        if not isinstance(asset, dict) or not isinstance(asset.get("asset_id"), str):
            continue
        settings = asset.get("default_settings", {})
        variants = settings.get("configuration_variants", []) if isinstance(settings, dict) else []
        if not isinstance(variants, list):
            continue
        for variant in variants:
            artifacts = variant.get("materialized_artifacts", []) if isinstance(variant, dict) else []
            if not isinstance(artifacts, list):
                continue
            for artifact in artifacts:
                if not isinstance(artifact, dict) or artifact.get("type") != "file":
                    continue
                path = artifact.get("path")
                if isinstance(path, str) and path:
                    paths_by_asset.setdefault(asset["asset_id"], set()).add(
                        f"/{path.lstrip('/')}"
                    )
    return paths_by_asset


def _is_configuration_materialized_path(
    materialized_paths: dict[str, set[str]],
    asset_id: str,
    rule_path: str,
) -> bool:
    paths = materialized_paths.get(asset_id, set())
    if rule_path in paths:
        return True
    if rule_path.endswith("/"):
        return any(path.startswith(rule_path) for path in paths)
    return False
