from __future__ import annotations

import json
import zipfile
from pathlib import Path

from libs.contracts.models import AssetDefinition
from services.profiler.attack_catalog import MitreAttackCatalog


ROOT = Path(__file__).resolve().parents[2]


def _catalog_by_id() -> dict[str, AssetDefinition]:
    payload = json.loads((ROOT / "data/assets/catalog.json").read_text(encoding="utf-8"))
    return {
        asset.asset_id: asset
        for asset in (AssetDefinition.model_validate(item) for item in payload)
    }


def test_static_internal_assets_have_nginx_runtime_and_files() -> None:
    assets = _catalog_by_id()
    expected_ports = {
        "internal-portal": 18080,
        "web-admin-console": 18081,
        "finance-share": 18082,
        "vpn-appliance": 18443,
        "malware-sink": 18085,
    }

    for asset_id, port in expected_ports.items():
        asset = assets[asset_id]
        runtime = asset.default_settings["runtime"]
        primary_volume = runtime["volumes"][0]

        assert asset.exposure_type == "internal"
        assert asset.telemetry_source == "asset_runtime"
        assert runtime["backend"] == "docker"
        assert runtime["image"] == "nginx:alpine"
        assert runtime["port_mappings"][0]["requested_host_port"] == port
        assert primary_volume == (
            f"{{host_project_root}}/deploy/internal-assets/{asset_id}/html:"
            "/usr/share/nginx/html:ro"
        )
        assert (ROOT / f"deploy/internal-assets/{asset_id}/html/index.html").exists()

    vpn_volumes = assets["vpn-appliance"].default_settings["runtime"]["volumes"]
    assert "{host_project_root}/deploy/internal-assets/vpn-appliance/nginx/default.conf:/etc/nginx/conf.d/default.conf:ro" in vpn_volumes
    assert "{host_project_root}/deploy/internal-assets/vpn-appliance/nginx/.htpasswd:/etc/nginx/.htpasswd:ro" in vpn_volumes


def test_static_internal_assets_include_breadcrumb_files() -> None:
    # These files are realistic breadcrumbs. Public-surface probes for similar
    # names should become evidence that can unlock related internal assets.
    breadcrumb_paths = [
        "deploy/internal-assets/finance-share/html/finance/archive/2024/budget-q4-review.xlsx",
        "deploy/internal-assets/finance-share/html/finance/archive/2024/payroll-archive.zip",
        "deploy/internal-assets/finance-share/html/finance/archive/2024/vendor-bank-change.csv",
        "deploy/internal-assets/finance-share/html/exports/db_backup_2024.sql.bak",
        "deploy/internal-assets/vpn-appliance/html/backup/ra-config-2026-04.bak",
        "deploy/internal-assets/vpn-appliance/html/download/contractor-profile.ovpn",
        "deploy/internal-assets/vpn-appliance/html/logs/vpn-auth.log",
        "deploy/internal-assets/vpn-appliance/html/policy/tunnel-routes.txt",
        "deploy/internal-assets/vpn-appliance/html/policy/failover-accounts.csv",
        "deploy/internal-assets/malware-sink/html/downloads/agent-update.bin",
        "deploy/internal-assets/malware-sink/html/upload/README.txt",
        "deploy/internal-assets/malware-sink/html/staging/manifest.json",
        "deploy/internal-assets/malware-sink/html/staging/tool-transfer-notes.txt",
        "deploy/internal-assets/malware-sink/html/staging/archive-plan.txt",
        "deploy/internal-assets/internal-portal/html/directory/hosts.csv",
        "deploy/internal-assets/internal-portal/html/directory/network-connections.csv",
        "deploy/internal-assets/web-admin-console/html/api/inventory.json",
        "deploy/internal-assets/web-admin-console/html/api/processes.json",
        "deploy/internal-assets/web-admin-console/html/api/network-connections.txt",
        "deploy/internal-assets/web-admin-console/html/api/groups.json",
        "deploy/internal-assets/web-admin-console/html/api/audit-log.csv",
        "deploy/internal-assets/web-admin-console/html/api/auth-policy.json",
        "deploy/internal-assets/web-admin-console/html/api/config-repositories.json",
        "deploy/internal-assets/web-admin-console/html/api/container-resources.json",
        "deploy/internal-assets/web-admin-console/html/api/account-lifecycle.json",
    ]

    for relative_path in breadcrumb_paths:
        path = ROOT / relative_path

        assert path.exists()
        assert path.stat().st_size > 0


def test_internal_asset_downloads_use_real_file_formats() -> None:
    xlsx_path = ROOT / "deploy/internal-assets/finance-share/html/finance/archive/2024/budget-q4-review.xlsx"
    payroll_path = ROOT / "deploy/internal-assets/finance-share/html/finance/archive/2024/payroll-archive.zip"
    agent_path = ROOT / "deploy/internal-assets/malware-sink/html/downloads/agent-update.bin"

    assert zipfile.is_zipfile(xlsx_path)
    with zipfile.ZipFile(xlsx_path) as workbook:
        names = set(workbook.namelist())

    assert "[Content_Types].xml" in names
    assert "xl/workbook.xml" in names
    assert "xl/worksheets/sheet1.xml" in names

    assert zipfile.is_zipfile(payroll_path)
    with zipfile.ZipFile(payroll_path) as archive:
        names = set(archive.namelist())

    assert "payroll-april.csv" in names
    assert "contractor-accounts.csv" in names
    assert "notes/password-rotation.txt" in names

    data = agent_path.read_bytes()
    assert data.startswith(b"NBAGENTPKG\x00")
    assert b"\x00" in data


def test_git_and_redis_seed_material_exists_for_realistic_future_runtime() -> None:
    seed_paths = [
        "deploy/internal-assets/git-internal/seed/infra-deploy/README.md",
        "deploy/internal-assets/git-internal/seed/infra-deploy/k8s/values-prod.yaml",
        "deploy/internal-assets/git-internal/seed/infra-deploy/runbooks/incident-admin-console.md",
        "deploy/internal-assets/git-internal/seed/customer-portal/config/application-prod.yml",
        "deploy/internal-assets/redis-cache/seed/keys.txt",
    ]

    for relative_path in seed_paths:
        path = ROOT / relative_path

        assert path.exists()
        assert path.stat().st_size > 0


def test_static_internal_asset_ports_are_wired_to_compose_and_env() -> None:
    enterprise = (ROOT / "docker-compose.enterprise.yml").read_text(encoding="utf-8")
    control = (ROOT / "docker-compose.control.yml").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    expected = {
        "FINANCE_SHARE_PORT": 18082,
        "VPN_APPLIANCE_PORT": 18443,
        "MALWARE_SINK_PORT": 18085,
    }

    for env_name, port in expected.items():
        asset_env = f"HONEYPOT_ASSET_{env_name}"

        assert f"{env_name}={port}" in env_example
        assert f"${{{env_name}:-{port}}}:{port}" in enterprise
        assert f'{asset_env}: "${{{env_name}:-{port}}}"' in control
        assert str(port) in env_example


def test_internal_assets_declare_public_http_unlock_signals() -> None:
    # Runtime dependency logic is catalog-driven, so each breadcrumb-backed
    # internal asset must declare the public HTTP signal that makes it eligible.
    assets = _catalog_by_id()
    expected = {
        "finance-share": "/backup/db_backup_2024.sql.bak",
        "git-internal": "/assets/app.js.map",
        "redis-cache": "/.env.old",
        "web-admin-console": "/admin",
        "ftp-archive": "/backup/passwords_internal.txt",
        "vpn-appliance": "/admin",
        "malware-sink": "public_http_exploit_probe",
    }

    for asset_id, expected_signal in expected.items():
        unlock_signals = assets[asset_id].default_settings["unlock_signals"]
        signal_values = [
            item
            for values in unlock_signals.values()
            for item in values
        ]

        assert expected_signal in signal_values


def test_internal_assets_declare_selection_profiles() -> None:
    # Selection metadata keeps the asset catalogue useful for controller scoring
    # without adding new top-level fields to the shared AssetDefinition schema.
    assets = _catalog_by_id()

    for asset in assets.values():
        selection_profile = asset.default_settings.get("selection_profile")

        assert isinstance(selection_profile, dict)
        assert selection_profile["reveal_outputs"]
        assert selection_profile["selection_notes"]
        assert isinstance(selection_profile["asset_group"], str)
        assert selection_profile["asset_group"]
        assert isinstance(selection_profile["covered_techniques"], list)
        assert selection_profile["covered_techniques"]
        assert isinstance(selection_profile["telemetry_value"], (int, float))
        assert 0 <= selection_profile["telemetry_value"] <= 1
        assert isinstance(selection_profile["optional_dependency_signals"], dict)
        telemetry_validation = asset.default_settings.get("telemetry_validation")
        assert isinstance(telemetry_validation, dict)
        assert telemetry_validation["kind"] == asset.telemetry_source
        assert telemetry_validation["expected_trigger"]
        if asset.telemetry_source in {"opencanary", "mailoney"}:
            assert isinstance(telemetry_validation["service"], str)
            assert telemetry_validation["service"]
        if asset.telemetry_source == "high_interaction":
            assert isinstance(telemetry_validation["source"], str)
            assert telemetry_validation["source"]

        tactic_difficulties = selection_profile["tactic_difficulties"]
        assert set(asset.covers_tactics).issubset(tactic_difficulties)
        for difficulty in tactic_difficulties.values():
            assert isinstance(difficulty, int)
            assert 1 <= difficulty <= 5


def test_configuration_variants_are_catalog_owned_and_target_existing_assets() -> None:
    assets = _catalog_by_id()
    catalog = MitreAttackCatalog(ROOT / "data/mitre/enterprise-attack.json")
    expected_variant_assets = {
        "internal-portal",
        "git-internal",
        "finance-share",
        "ops-db",
        "redis-cache",
        "web-admin-console",
        "vpn-appliance",
        "malware-sink",
        "ssh-canary",
        "ftp-archive",
        "legacy-telnet",
        "mail-relay",
        "admin-jumpbox",
        "dionaea-capture",
        "honeytrap-generic",
    }

    for asset in assets.values():
        variants = asset.default_settings.get("configuration_variants", [])
        assert isinstance(variants, list)
        for variant in variants:
            assert isinstance(variant["configuration_id"], str)
            assert isinstance(variant["kind"], str)
            assert isinstance(variant["required_markers"], list)
            assert variant["required_markers"]
            assert isinstance(variant["covered_techniques"], list)
            assert variant["covered_techniques"]
            for technique in variant["covered_techniques"]:
                assert catalog.tactic_for_technique(technique) is not None
            assert isinstance(variant["telemetry_value"], (int, float))
            assert 0 <= variant["telemetry_value"] <= 1
            assert isinstance(variant["reason"], str)
            assert variant["reason"]
            target_asset_id = variant.get("target_asset_id")
            if target_asset_id is not None:
                assert target_asset_id in assets

    for asset_id in expected_variant_assets:
        assert assets[asset_id].default_settings["configuration_variants"]


def test_internal_asset_covered_techniques_exist_in_enterprise_attack() -> None:
    catalog = MitreAttackCatalog(ROOT / "data/mitre/enterprise-attack.json")
    assets = _catalog_by_id()

    for asset in assets.values():
        selection_profile = asset.default_settings["selection_profile"]
        for technique in selection_profile["covered_techniques"]:
            assert catalog.tactic_for_technique(technique) is not None


def test_web_admin_console_has_no_default_external_lab_upgrade() -> None:
    assets = _catalog_by_id()
    selection_profile = assets["web-admin-console"].default_settings["selection_profile"]

    assert "upgrade_candidates" not in selection_profile


def test_runtime_capture_assets_declare_real_runtime_and_gateway_ports() -> None:
    assets = _catalog_by_id()
    expected_ports = {
        "dionaea-capture": ("high", {18085, 1445, 11433, 12122}),
        "honeytrap-generic": ("medium", {19999}),
    }

    for asset_id, (interaction_level, public_ports) in expected_ports.items():
        asset = assets[asset_id]
        runtime = asset.default_settings["runtime"]
        mappings = runtime["port_mappings"]

        assert asset.interaction_level == interaction_level
        assert asset.telemetry_source == "high_interaction"
        assert runtime["backend"] in {"docker", "compose"}
        assert {item["requested_host_port"] for item in mappings} == public_ports

    assert assets["dionaea-capture"].dependencies == ["malware-sink"]
    assert assets["honeytrap-generic"].dependencies == ["malware-sink"]
