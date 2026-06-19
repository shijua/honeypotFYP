from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_public_portal_exposes_expected_breadcrumb_files() -> None:
    # Public portal breadcrumbs are discoverable by suspicious HTTP probing, and
    # the resulting evidence drives internal asset dependencies.
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


def test_public_portal_env_old_contains_realistic_breadcrumb_values() -> None:
    content = (ROOT / "deploy/public-portal/html/.env.old").read_text(encoding="utf-8")

    assert "DB_HOST=db01.internal.local" in content
    assert "DB_PORT=13306" in content
    assert "REDIS_PORT=16379" in content
    assert "INTERNAL_PORTAL_URL=http://intranet.internal.local:18080" in content
    assert "GITEA_URL=git://git.internal.local:19418/infra-deploy.git" in content
    assert "GITEA_TOKEN=nbg_git_ro_2026_04_legacy" in content
    assert "INTERNAL_API_KEY=nb_api_ro_2026_04_status" in content
    assert "PORTAL_READER_TOKEN=nbp_reader_2026_04_window" in content


def test_public_portal_uses_realistic_compatibility_headers() -> None:
    nginx_conf = (ROOT / "deploy/public-portal/nginx.conf").read_text(encoding="utf-8")

    assert 'add_header X-Origin-Server "Apache/2.4.49" always;' in nginx_conf
    assert 'add_header X-Powered-By "PHP/7.4" always;' in nginx_conf
    assert 'add_header X-Backend-Server "intranet-web-01" always;' in nginx_conf


def test_attacker_visible_files_do_not_explain_their_role() -> None:
    visible_roots = [
        ROOT / "deploy/public-portal/html",
        ROOT / "deploy/internal-assets",
    ]
    banned = [
        re.compile(r"\bfake\b", re.IGNORECASE),
        re.compile(r"\bdecoy\b", re.IGNORECASE),
        re.compile(r"\bhoneypot\b", re.IGNORECASE),
        re.compile(r"\blure\b", re.IGNORECASE),
        re.compile(r"not real", re.IGNORECASE),
        re.compile(r"\bDECOY\b", re.IGNORECASE),
        re.compile(r"testing only", re.IGNORECASE),
    ]

    for root in visible_roots:
        for path in root.rglob("*"):
            if path.is_file():
                content = path.read_text(encoding="utf-8", errors="ignore")
                for pattern in banned:
                    assert not pattern.search(content), f"{pattern.pattern} found in {path}"
