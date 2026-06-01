from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from libs.contracts.models import (
    CowrieIngestRequest,
    CowrieLogEvent,
    EntrypointCaptureRequest,
    HighInteractionIngestRequest,
    HighInteractionLogEvent,
    OpenCanaryIngestRequest,
    OpenCanaryLogEvent,
)
from services.binding_service.domain import BindingService
from services.cowrie.command_mapping import (
    CompositeCowrieCommandRuleCatalog,
    FileCowrieCommandRuleCatalog,
)
from services.cowrie.domain import CowrieService
from services.cowrie.event_catalog import FileCowrieEventCatalog
from services.cowrie.sigma_mapping import SigmaCowrieCommandRuleCatalog
from services.entrypoint.domain import EntrypointService
from services.high_interaction.domain import HighInteractionService
from services.opencanary.domain import OpenCanaryService
from services.profiler.domain import ProfilerService
from tests.support.attack_catalog import build_test_attack_catalog
from tests.support.inmemory_repositories import (
    InMemoryBindingRepository,
    InMemoryCowrieObservationRepository,
    InMemoryEntrypointObservationRepository,
    InMemoryEvidenceRepository,
    InMemoryHighInteractionObservationRepository,
    InMemoryOpenCanaryObservationRepository,
    InMemoryProfileRepository,
)


pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[2]


TECHNIQUE_ACCESS_SAMPLES: dict[str, tuple[str, dict[str, Any]]] = {
    "T1003": ("cowrie", {"input": "cat /etc/shadow"}),
    "T1005": ("http", {"asset_id": "finance-share", "path": "/finance/archive/2024/payroll-archive.zip"}),
    "T1016": ("cowrie", {"input": "ip addr"}),
    "T1018": ("http", {"asset_id": "internal-portal", "path": "/directory/hosts.csv"}),
    "T1021": ("opencanary", {"service": "ftp", "dst_port": 21, "logdata": {"SERVICE": "ftp", "USERNAME": "operator", "PASSWORD": "x"}}),
    "T1021.004": ("opencanary", {"service": "ssh", "dst_port": 22, "logdata": {"SERVICE": "ssh", "USERNAME": "root", "PASSWORD": "x"}}),
    "T1033": ("cowrie", {"input": "whoami"}),
    "T1039": ("opencanary", {"service": "ftp", "dst_port": 21, "logdata": {"SERVICE": "ftp", "COMMAND": "RETR finance-drop.zip"}}),
    "T1041": ("high_interaction", {"source": "dionaea", "asset_id": "dionaea-capture", "service": "http", "event_type": "download.offer", "logdata": {"message": "payload download"}}),
    "T1046": ("opencanary", {"service": "redis", "dst_port": 6379, "logdata": {"SERVICE": "redis", "COMMAND": "INFO"}}),
    "T1053": ("cowrie", {"input": "crontab -l"}),
    "T1057": ("http", {"asset_id": "web-admin-console", "path": "/api/processes.json"}),
    "T1059": ("cowrie", {"input": "bash -i"}),
    "T1069": ("http", {"asset_id": "web-admin-console", "path": "/api/groups.json"}),
    "T1070": ("cowrie", {"input": "history -c"}),
    "T1074": ("http", {"asset_id": "malware-sink", "path": "/staging/archive-plan.txt"}),
    # `auth_result=success` is a synthetic success marker emitted by the
    # internal login flow/test harness; a plain token POST is only T1110.
    "T1078": ("http", {"asset_id": "internal-portal", "method": "POST", "path": "/session", "body": "username=portal.reader&token=x&auth_result=success", "dynamic_endpoint": True}),
    "T1082": ("http", {"asset_id": "web-admin-console", "path": "/api/container-resources.json"}),
    "T1083": ("cowrie", {"input": "ls -la /tmp"}),
    "T1087.003": ("opencanary", {"service": "smtp", "dst_port": 25, "logdata": {"SERVICE": "smtp", "COMMANDS": ["VRFY finance"]}}),
    "T1105": ("http", {"asset_id": "malware-sink", "path": "/downloads/agent-update.bin"}),
    "T1110": ("http", {"asset_id": "web-admin-console", "method": "POST", "path": "/login", "body": "username=admin&password=x", "dynamic_endpoint": True}),
    "T1133": ("http", {"asset_id": "vpn-appliance", "path": "/download/contractor-profile.ovpn"}),
    "T1190": ("high_interaction", {"source": "honeytrap", "asset_id": "honeytrap-generic", "service": "tcp", "event_type": "payload.transfer", "logdata": {"message": "binary payload upload"}}),
    "T1204.002": ("high_interaction", {"source": "dionaea", "asset_id": "dionaea-capture", "service": "http", "event_type": "download.offer", "logdata": {"message": "payload download"}}),
    "T1213": ("opencanary", {"service": "git", "dst_port": 9418, "logdata": {"SERVICE": "git", "REPO": "infra-deploy.git"}}),
    "T1518": ("http", {"asset_id": "web-admin-console", "path": "/api/inventory.json"}),
    "T1548": ("cowrie", {"input": "sudo -l"}),
    "T1552.001": ("cowrie", {"input": "grep password .env"}),
    "T1567": ("http", {"asset_id": "malware-sink", "method": "POST", "path": "/upload/", "body": "filename=finance-drop.zip", "dynamic_endpoint": True}),
    "T1567.002": ("opencanary", {"service": "ftp", "dst_port": 21, "logdata": {"SERVICE": "ftp", "COMMAND": "STOR finance-drop.zip"}}),
    "T1572": ("http", {"asset_id": "vpn-appliance", "path": "/policy/tunnel-routes.txt"}),
    "T1608": ("http", {"asset_id": "malware-sink", "path": "/staging/manifest.json"}),
}


CATALOG_ACCESS_CASES: dict[str, set[str]] = {
    "internal-portal": {"T1046", "T1083", "T1018"},
    "internal-portal:portal-api-directory-links": {"T1046", "T1083", "T1018"},
    "internal-portal:portal-admin-console-link": {"T1078", "T1110"},
    "finance-share": {"T1005", "T1074"},
    "finance-share:finance-backup-archive-index": {"T1005", "T1074"},
    "finance-share:finance-password-rotation-clue": {"T1552.001"},
    "git-internal": {"T1213", "T1083"},
    "git-internal:git-seeded-repository-backend": {"T1213", "T1083"},
    "ops-db": {"T1078", "T1110"},
    "ops-db:ops-db-schema-banner-backend": {"T1078", "T1110"},
    "admin-jumpbox": {"T1059", "T1033", "T1082"},
    "admin-jumpbox:jumpbox-cowrie-operator-profile": {"T1059", "T1033", "T1082"},
    "redis-cache": {"T1046", "T1005"},
    "redis-cache:redis-seeded-keyspace-backend": {"T1046", "T1005"},
    "web-admin-console": {"T1078", "T1110"},
    "web-admin-console:web-admin-login-surface": {"T1078", "T1110"},
    "web-admin-console:web-admin-discovery-endpoints": {"T1082", "T1057", "T1069", "T1518"},
    "ftp-archive": {"T1005", "T1039"},
    "ftp-archive:ftp-archive-review-banner": {"T1005", "T1039"},
    "ssh-canary": {"T1021.004", "T1110"},
    "ssh-canary:ssh-cowrie-jumpbox-profile": {"T1021.004", "T1110"},
    "legacy-telnet": {"T1046", "T1021"},
    "legacy-telnet:legacy-telnet-console-prompt": {"T1046", "T1021"},
    "mail-relay": {"T1046", "T1087.003"},
    "mail-relay:mailoney-auth-relay-backend": {"T1087.003", "T1110"},
    "vpn-appliance": {"T1133", "T1078"},
    "vpn-appliance:vpn-profile-login-clue": {"T1078", "T1133"},
    "vpn-appliance:vpn-route-policy-notes": {"T1016", "T1021", "T1572"},
    "malware-sink": {"T1105", "T1074"},
    "malware-sink:malware-downloader-staging-directory": {"T1105", "T1608"},
    "malware-sink:malware-upload-drop-endpoint": {"T1105", "T1041", "T1567"},
    "malware-sink:malware-dionaea-same-port-upgrade": {"T1105", "T1204.002", "T1041", "T1190"},
    "malware-sink:malware-honeytrap-generic-listener": {"T1046", "T1105", "T1190"},
    "dionaea-capture": {"T1105"},
    "dionaea-capture:dionaea-to-glutton-http-capture": {"T1190", "T1105"},
    "honeytrap-generic": {"T1046", "T1190"},
    "honeytrap-generic:honeytrap-wordpot-web-capture": {"T1190", "T1046"},
}


CONFIGURATION_ARTIFACT_ACCESS_SAMPLES: dict[str, tuple[set[str], tuple[str, dict[str, Any]]]] = {
    "internal-portal:portal-api-directory-links:openapi": (
        {"T1018", "T1046"},
        ("http", {"asset_id": "internal-portal", "path": "/api/openapi-summary.json", "dynamic_endpoint": True}),
    ),
    "internal-portal:portal-api-directory-links:runbook": (
        {"T1018", "T1046"},
        ("http", {"asset_id": "internal-portal", "path": "/runbooks/service-directory.md", "dynamic_endpoint": True}),
    ),
    "internal-portal:portal-admin-console-link": (
        {"T1213"},
        ("http", {"asset_id": "internal-portal", "path": "/runbooks/admin-console-access.md", "dynamic_endpoint": True}),
    ),
    "finance-share:finance-backup-archive-index:index": (
        {"T1005"},
        ("http", {"asset_id": "finance-share", "path": "/finance/archive/2024/customer-export-index.csv", "dynamic_endpoint": True}),
    ),
    "finance-share:finance-backup-archive-index:manifest": (
        {"T1005"},
        ("http", {"asset_id": "finance-share", "path": "/finance/archive/2024/archive-manifest.txt", "dynamic_endpoint": True}),
    ),
    "finance-share:finance-password-rotation-clue": (
        {"T1213"},
        ("http", {"asset_id": "finance-share", "path": "/finance/archive/2024/password-rotation-note.txt", "dynamic_endpoint": True}),
    ),
    "web-admin-console:web-admin-login-surface": (
        set(),
        ("http", {"asset_id": "web-admin-console", "path": "/login/", "dynamic_endpoint": True}),
    ),
    "web-admin-console:web-admin-discovery-endpoints:inventory": (
        {"T1518"},
        ("http", {"asset_id": "web-admin-console", "path": "/api/inventory.json"}),
    ),
    "web-admin-console:web-admin-discovery-endpoints:processes": (
        {"T1057"},
        ("http", {"asset_id": "web-admin-console", "path": "/api/processes.json"}),
    ),
    "web-admin-console:web-admin-discovery-endpoints:groups": (
        {"T1069"},
        ("http", {"asset_id": "web-admin-console", "path": "/api/groups.json"}),
    ),
    "vpn-appliance:vpn-profile-login-clue": (
        {"T1133"},
        ("http", {"asset_id": "vpn-appliance", "path": "/policy/login-clue.txt", "dynamic_endpoint": True}),
    ),
    "vpn-appliance:vpn-route-policy-notes": (
        {"T1016"},
        ("http", {"asset_id": "vpn-appliance", "path": "/policy/route-policy-notes.txt", "dynamic_endpoint": True}),
    ),
    "malware-sink:malware-downloader-staging-directory": (
        {"T1608"},
        ("http", {"asset_id": "malware-sink", "path": "/staging/downloader-index.txt", "dynamic_endpoint": True}),
    ),
    "malware-sink:malware-upload-drop-endpoint": (
        set(),
        ("http", {"asset_id": "malware-sink", "path": "/upload/drop-endpoint.txt", "dynamic_endpoint": True}),
    ),
}


def test_access_cases_cover_every_catalog_asset_and_configuration_target() -> None:
    assert set(CATALOG_ACCESS_CASES) == set(_catalog_target_techniques())


def test_access_cases_match_declared_target_techniques() -> None:
    assert CATALOG_ACCESS_CASES == _catalog_target_techniques()


@pytest.mark.parametrize("target_id", sorted(CATALOG_ACCESS_CASES))
def test_access_cases_map_to_declared_target_techniques(target_id: str) -> None:
    mapped = _mapped_techniques_for_target(target_id)

    assert CATALOG_ACCESS_CASES[target_id].issubset(mapped)


@pytest.mark.parametrize(
    ("technique", "sample"),
    sorted(TECHNIQUE_ACCESS_SAMPLES.items()),
)
def test_individual_access_samples_update_profile(technique: str, sample: tuple[str, dict[str, Any]]) -> None:
    assert technique in _techniques_from_sample(*sample)


def test_http_access_case_paths_exist_or_are_declared_dynamic() -> None:
    for technique, (kind, payload) in TECHNIQUE_ACCESS_SAMPLES.items():
        if kind != "http" or str(payload.get("method", "GET")).upper() != "GET":
            continue
        if payload.get("dynamic_endpoint"):
            continue

        asset_path = (
            ROOT
            / "deploy/internal-assets"
            / str(payload["asset_id"])
            / "html"
            / str(payload["path"]).lstrip("/")
        )
        assert asset_path.exists(), f"{technique} sample path does not exist: {asset_path}"


def test_non_get_http_access_cases_are_declared_dynamic() -> None:
    for technique, (kind, payload) in TECHNIQUE_ACCESS_SAMPLES.items():
        if kind == "http" and str(payload.get("method", "GET")).upper() != "GET":
            assert payload.get("dynamic_endpoint") is True, technique


@pytest.mark.parametrize(
    ("case_id", "expected", "sample"),
    [
        (case_id, expected, sample)
        for case_id, (expected, sample) in sorted(CONFIGURATION_ARTIFACT_ACCESS_SAMPLES.items())
    ],
)
def test_configuration_artifact_access_updates_profile(
    case_id: str,
    expected: set[str],
    sample: tuple[str, dict[str, Any]],
) -> None:
    mapped = _techniques_from_sample(*sample)

    assert mapped == expected, case_id


def _catalog_target_techniques() -> dict[str, set[str]]:
    catalog = json.loads((ROOT / "data/assets/catalog.json").read_text(encoding="utf-8"))
    target_techniques: dict[str, set[str]] = {}
    for asset in catalog:
        if not isinstance(asset, dict) or not isinstance(asset.get("asset_id"), str):
            continue
        asset_id = asset["asset_id"]
        settings = asset.get("default_settings", {}) if isinstance(asset, dict) else {}
        profile = settings.get("selection_profile", {}) if isinstance(settings, dict) else {}
        if isinstance(profile, dict):
            target_techniques[asset_id] = _strings(profile.get("covered_techniques"))
        variants = settings.get("configuration_variants", []) if isinstance(settings, dict) else []
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict) and isinstance(variant.get("configuration_id"), str):
                    target_techniques[
                        f"{asset_id}:{variant['configuration_id']}"
                    ] = _strings(variant.get("covered_techniques"))
    return target_techniques


def _mapped_techniques_for_target(target_id: str) -> set[str]:
    mapped: set[str] = set()
    missing_samples = CATALOG_ACCESS_CASES[target_id] - set(TECHNIQUE_ACCESS_SAMPLES)
    assert missing_samples == set()
    for technique in CATALOG_ACCESS_CASES[target_id]:
        mapped.update(_techniques_from_sample(*TECHNIQUE_ACCESS_SAMPLES[technique]))
    return mapped


def _techniques_from_sample(kind: str, payload: dict[str, Any]) -> set[str]:
    if kind == "http":
        response = _entrypoint_service().capture_http_request(
            EntrypointCaptureRequest(
                attacker_key=f"198.51.100.{abs(hash(str(payload))) % 90 + 10}",
                method=str(payload.get("method", "GET")),
                path=str(payload["path"]),
                headers={"user-agent": "curl/8.0"},
                body_preview=str(payload.get("body", "")),
                surface="internal",
                asset_id=str(payload["asset_id"]),
            )
        )
        return set(response.profile.recent_techniques)
    if kind == "high_interaction":
        response = _high_interaction_service().ingest(
            HighInteractionIngestRequest(
                event=HighInteractionLogEvent(
                    source=str(payload["source"]),
                    asset_id=str(payload["asset_id"]),
                    attacker_key=f"198.51.100.{abs(hash(str(payload))) % 90 + 10}",
                    service=str(payload["service"]),
                    event_type=str(payload["event_type"]),
                    logdata=dict(payload.get("logdata", {})),
                )
            )
        )
        return set(response.profile.recent_techniques)
    if kind == "opencanary":
        response = _opencanary_service().ingest(
            OpenCanaryIngestRequest(
                event=OpenCanaryLogEvent(
                    src_host=f"198.51.100.{abs(hash(str(payload))) % 90 + 10}",
                    dst_port=int(payload["dst_port"]),
                    utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    node_id=f"opencanary-{payload['service']}",
                    logdata=dict(payload.get("logdata", {})),
                ),
                protocol=str(payload["service"]),
            )
        )
        return set(response.profile.recent_techniques)
    if kind == "cowrie":
        response = _cowrie_service().ingest(
            CowrieIngestRequest(
                event=CowrieLogEvent(
                    eventid="cowrie.command.input",
                    timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                    src_ip=f"198.51.100.{abs(hash(str(payload))) % 90 + 10}",
                    session="s-catalog",
                    input=str(payload["input"]),
                )
            )
        )
        return set(response.profile.recent_techniques)
    raise AssertionError(f"unknown sample kind {kind}")


def _strings(value: object) -> set[str]:
    return {item for item in value if isinstance(item, str)} if isinstance(value, list) else set()


def _profiler() -> ProfilerService:
    return ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )


def _binding_service() -> BindingService:
    return BindingService(InMemoryBindingRepository())


def _entrypoint_service() -> EntrypointService:
    return EntrypointService(
        _binding_service(),
        InMemoryEntrypointObservationRepository(),
        profiler_service=_profiler(),
    )


def _high_interaction_service() -> HighInteractionService:
    return HighInteractionService(
        _binding_service(),
        _profiler(),
        InMemoryHighInteractionObservationRepository(),
    )


def _opencanary_service() -> OpenCanaryService:
    return OpenCanaryService(
        _binding_service(),
        _profiler(),
        InMemoryOpenCanaryObservationRepository(),
    )


def _cowrie_service() -> CowrieService:
    return CowrieService(
        _binding_service(),
        _profiler(),
        InMemoryCowrieObservationRepository(),
        FileCowrieEventCatalog("data/cowrie/event_mappings.json"),
        CompositeCowrieCommandRuleCatalog(
            (
                FileCowrieCommandRuleCatalog("data/cowrie/command_mapping_rules.json"),
                SigmaCowrieCommandRuleCatalog("data/detections/cowrie_sigma"),
            )
        ),
    )
