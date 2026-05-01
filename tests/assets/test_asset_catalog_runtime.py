from __future__ import annotations

import json
from pathlib import Path

from libs.contracts.models import AssetDefinition


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
        "ics-plc": 18084,
        "vpn-appliance": 18443,
        "malware-sink": 18085,
    }

    for asset_id, port in expected_ports.items():
        asset = assets[asset_id]
        runtime = asset.default_settings["runtime"]
        volume = runtime["volumes"][0]

        assert asset.exposure_type == "internal"
        assert asset.telemetry_source == "asset_runtime"
        assert runtime["backend"] == "docker"
        assert runtime["image"] == "nginx:alpine"
        assert runtime["port_mappings"][0]["requested_host_port"] == port
        assert volume == (
            f"{{host_project_root}}/deploy/internal-assets/{asset_id}/html:"
            "/usr/share/nginx/html:ro"
        )
        assert (ROOT / f"deploy/internal-assets/{asset_id}/html/index.html").exists()


def test_static_internal_assets_include_breadcrumb_files() -> None:
    # These files are realistic breadcrumbs. Public-surface probes for similar
    # names should become evidence that can unlock related internal assets.
    breadcrumb_paths = [
        "deploy/internal-assets/finance-share/html/finance/archive/2024/budget-q4-review.xlsx",
        "deploy/internal-assets/finance-share/html/finance/archive/2024/payroll-archive.zip",
        "deploy/internal-assets/finance-share/html/finance/archive/2024/vendor-bank-change.csv",
        "deploy/internal-assets/finance-share/html/exports/db_backup_2024.sql.bak",
        "deploy/internal-assets/ics-plc/html/config/plc-backup-2026-04.cfg",
        "deploy/internal-assets/ics-plc/html/maps/modbus-unit-map.csv",
        "deploy/internal-assets/vpn-appliance/html/backup/ra-config-2026-04.bak",
        "deploy/internal-assets/vpn-appliance/html/download/contractor-profile.ovpn",
        "deploy/internal-assets/vpn-appliance/html/logs/vpn-auth.log",
        "deploy/internal-assets/malware-sink/html/downloads/agent-update.bin",
        "deploy/internal-assets/malware-sink/html/upload/README.txt",
    ]

    for relative_path in breadcrumb_paths:
        path = ROOT / relative_path

        assert path.exists()
        assert path.stat().st_size > 0


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
        "ICS_PLC_PORT": 18084,
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
        "ics-plc": "/internal-api/status",
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

        tactic_difficulties = selection_profile["tactic_difficulties"]
        assert set(asset.covers_tactics).issubset(tactic_difficulties)
        for difficulty in tactic_difficulties.values():
            assert isinstance(difficulty, int)
            assert 1 <= difficulty <= 5
