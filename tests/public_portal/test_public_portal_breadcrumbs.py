from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_public_portal_exposes_expected_fake_breadcrumb_files() -> None:
    # Public portal files are fake breadcrumbs. Attackers can discover them, and
    # the resulting public HTTP evidence drives internal asset dependencies.
    expected_paths = [
        "deploy/public-portal/html/.env.old",
        "deploy/public-portal/html/backup/db_backup_2024.sql.bak",
        "deploy/public-portal/html/backup/passwords_internal.txt",
        "deploy/public-portal/html/assets/app.js",
        "deploy/public-portal/html/assets/app.js.map",
        "deploy/public-portal/html/phpinfo.php",
    ]

    for relative_path in expected_paths:
        path = ROOT / relative_path

        assert path.exists()
        assert path.stat().st_size > 0


def test_public_portal_fake_env_old_contains_only_decoy_values() -> None:
    content = (ROOT / "deploy/public-portal/html/.env.old").read_text(encoding="utf-8")

    assert "DB_HOST=db01.internal.local" in content
    assert "GITEA_TOKEN=DECOY_GITEA_TOKEN_PUBLIC_SURFACE" in content
    assert "INTERNAL_API_KEY=DECOY_INTERNAL_API_KEY_PUBLIC_SURFACE" in content
    assert "not real secrets" in content


def test_public_portal_uses_decoy_headers_instead_of_claiming_real_server_header() -> None:
    nginx_conf = (ROOT / "deploy/public-portal/nginx.conf").read_text(encoding="utf-8")

    assert 'add_header X-Decoy-Server "Apache/2.4.49" always;' in nginx_conf
    assert 'add_header X-Powered-By "PHP/7.4" always;' in nginx_conf
    assert 'add_header X-Backend-Server "intranet-web-01" always;' in nginx_conf
