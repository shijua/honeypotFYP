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


CATALOG_TECHNIQUE_ACCESS_SAMPLES: dict[str, tuple[str, dict[str, Any]]] = {
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
    "T1078": ("http", {"asset_id": "internal-portal", "method": "POST", "path": "/session", "body": "username=portal.reader&token=x&auth_result=success"}),
    "T1082": ("http", {"asset_id": "web-admin-console", "path": "/api/container-resources.json"}),
    "T1083": ("cowrie", {"input": "ls -la /tmp"}),
    "T1087.001": ("cowrie", {"input": "cat /etc/passwd"}),
    "T1087.003": ("opencanary", {"service": "smtp", "dst_port": 25, "logdata": {"SERVICE": "smtp", "COMMANDS": ["VRFY finance"]}}),
    "T1105": ("http", {"asset_id": "malware-sink", "path": "/downloads/agent-update.bin"}),
    "T1110": ("http", {"asset_id": "web-admin-console", "method": "POST", "path": "/login", "body": "username=admin&password=x"}),
    "T1133": ("http", {"asset_id": "vpn-appliance", "path": "/download/contractor-profile.ovpn"}),
    "T1190": ("high_interaction", {"source": "honeytrap", "asset_id": "honeytrap-generic", "service": "tcp", "event_type": "payload.transfer", "logdata": {"message": "binary payload upload"}}),
    "T1204.002": ("high_interaction", {"source": "dionaea", "asset_id": "dionaea-capture", "service": "http", "event_type": "download.offer", "logdata": {"message": "payload download"}}),
    "T1213": ("opencanary", {"service": "git", "dst_port": 9418, "logdata": {"SERVICE": "git", "REPO": "infra-deploy.git"}}),
    "T1518": ("http", {"asset_id": "web-admin-console", "path": "/api/inventory.json"}),
    "T1548": ("cowrie", {"input": "sudo -l"}),
    "T1552.001": ("cowrie", {"input": "grep password .env"}),
    "T1567": ("http", {"asset_id": "malware-sink", "method": "POST", "path": "/upload/", "body": "filename=finance-drop.zip"}),
    "T1567.002": ("opencanary", {"service": "ftp", "dst_port": 21, "logdata": {"SERVICE": "ftp", "COMMAND": "STOR finance-drop.zip"}}),
    "T1572": ("http", {"asset_id": "vpn-appliance", "path": "/policy/tunnel-routes.txt"}),
    "T1608": ("http", {"asset_id": "malware-sink", "path": "/staging/manifest.json"}),
}


CURRENT_EXACT_MAPPING_GAPS: set[str] = set()


def test_access_sample_matrix_covers_all_catalog_techniques() -> None:
    missing = _catalog_techniques() - set(CATALOG_TECHNIQUE_ACCESS_SAMPLES)

    assert missing == set()


def test_existing_access_mappers_have_explicit_catalog_technique_gaps() -> None:
    observed_gaps = {
        technique
        for technique, sample in CATALOG_TECHNIQUE_ACCESS_SAMPLES.items()
        if technique not in _techniques_from_sample(*sample)
    }

    assert observed_gaps == CURRENT_EXACT_MAPPING_GAPS


@pytest.mark.parametrize(
    "technique",
    sorted(set(CATALOG_TECHNIQUE_ACCESS_SAMPLES) - CURRENT_EXACT_MAPPING_GAPS),
)
def test_supported_catalog_technique_access_sample_updates_profile(technique: str) -> None:
    mapped = _techniques_from_sample(*CATALOG_TECHNIQUE_ACCESS_SAMPLES[technique])

    assert technique in mapped


@pytest.mark.parametrize(
    ("asset_id", "method", "path", "body", "expected_techniques"),
    [
        ("internal-portal", "POST", "/session", "username=portal.reader&token=x&auth_result=success", {"T1110", "T1021"}),
        ("finance-share", "GET", "/finance/archive/2024/payroll-archive.zip", "", {"T1005"}),
        ("web-admin-console", "POST", "/login", "username=admin&password=x", {"T1110"}),
        ("vpn-appliance", "GET", "/download/contractor-profile.ovpn", "", {"T1133"}),
        ("malware-sink", "GET", "/downloads/agent-update.bin", "", {"T1105"}),
        ("malware-sink", "POST", "/upload/", "filename=finance-drop.zip", {"T1567"}),
    ],
)
def test_internal_http_asset_access_uses_sigma_to_update_techniques(
    asset_id: str,
    method: str,
    path: str,
    body: str,
    expected_techniques: set[str],
) -> None:
    response = _entrypoint_service().capture_http_request(
        EntrypointCaptureRequest(
            attacker_key=f"198.51.100.{10 + len(asset_id)}",
            method=method,
            path=path,
            headers={"user-agent": "curl/8.0"},
            body_preview=body,
            surface="internal",
            asset_id=asset_id,
        )
    )

    assert expected_techniques.issubset(set(response.profile.recent_techniques))
    assert response.profile.recent_asset_ids == [asset_id]


@pytest.mark.parametrize(
    ("asset_id", "source", "service", "event_type", "logdata", "expected_techniques"),
    [
        (
            "dionaea-capture",
            "dionaea",
            "http",
            "download.offer",
            {"url": "/downloads/agent-update.bin", "message": "payload download"},
            {"T1190", "T1204.002", "T1105", "T1041"},
        ),
        (
            "honeytrap-generic",
            "honeytrap",
            "tcp",
            "payload.transfer",
            {"message": "binary payload upload"},
            {"T1046", "T1190", "T1105"},
        ),
    ],
)
def test_high_interaction_asset_access_uses_sigma_to_update_techniques(
    asset_id: str,
    source: str,
    service: str,
    event_type: str,
    logdata: dict[str, object],
    expected_techniques: set[str],
) -> None:
    response = _high_interaction_service().ingest(
        HighInteractionIngestRequest(
            event=HighInteractionLogEvent(
                source=source,
                asset_id=asset_id,
                attacker_key=f"198.51.100.{20 + len(asset_id)}",
                service=service,
                event_type=event_type,
                logdata=logdata,
            )
        )
    )

    assert expected_techniques.issubset(set(response.profile.recent_techniques))
    assert response.profile.recent_asset_ids == [asset_id]


@pytest.mark.parametrize(
    ("asset_id", "service_name", "dst_port", "logdata", "expected_techniques"),
    [
        ("git-internal", "git", 9418, {"SERVICE": "git", "REPO": "infra-deploy.git"}, {"T1046", "T1213"}),
        ("ops-db", "mysql", 3306, {"SERVICE": "mysql", "USERNAME": "backup", "PASSWORD": "x"}, {"T1110"}),
        ("redis-cache", "redis", 6379, {"SERVICE": "redis", "COMMAND": "KEYS"}, {"T1046", "T1213"}),
        ("ftp-archive", "ftp", 21, {"SERVICE": "ftp", "USERNAME": "operator", "PASSWORD": "x"}, {"T1110", "T1021"}),
        ("ftp-archive", "ftp", 21, {"SERVICE": "ftp", "COMMAND": "RETR finance-drop.zip"}, {"T1039"}),
        ("ftp-archive", "ftp", 21, {"SERVICE": "ftp", "COMMAND": "STOR finance-drop.zip"}, {"T1567.002"}),
        ("ssh-canary", "ssh", 22, {"SERVICE": "ssh", "USERNAME": "root", "PASSWORD": "x"}, {"T1110", "T1021"}),
        ("legacy-telnet", "telnet", 23, {"SERVICE": "telnet", "USERNAME": "operator", "PASSWORD": "x"}, {"T1110", "T1021"}),
        ("mail-relay", "smtp", 25, {"SERVICE": "smtp", "COMMANDS": ["VRFY finance"]}, {"T1087.003"}),
        ("mail-relay", "smtp", 25, {"SERVICE": "smtp", "COMMANDS": ["EHLO", "AUTH", "QUIT"]}, {"T1110"}),
    ],
)
def test_opencanary_asset_access_updates_techniques(
    asset_id: str,
    service_name: str,
    dst_port: int,
    logdata: dict[str, object],
    expected_techniques: set[str],
) -> None:
    response = _opencanary_service().ingest(
        OpenCanaryIngestRequest(
            event=OpenCanaryLogEvent(
                src_host=f"198.51.100.{30 + dst_port % 10}",
                dst_port=dst_port,
                utc_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
                node_id=f"opencanary-{asset_id}",
                logdata=logdata,
            ),
            protocol=service_name,
        )
    )

    assert expected_techniques.issubset(set(response.profile.recent_techniques))


def test_admin_jumpbox_cowrie_command_updates_techniques() -> None:
    response = _cowrie_service().ingest(
        CowrieIngestRequest(
            event=CowrieLogEvent(
                eventid="cowrie.command.input",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                src_ip="198.51.100.77",
                session="s-admin",
                input="ls -la /tmp",
            )
        )
    )

    assert "T1083" in response.profile.recent_techniques


def _catalog_techniques() -> set[str]:
    catalog = json.loads((ROOT / "data/assets/catalog.json").read_text(encoding="utf-8"))
    techniques: set[str] = set()
    for asset in catalog:
        settings = asset.get("default_settings", {}) if isinstance(asset, dict) else {}
        profile = settings.get("selection_profile", {}) if isinstance(settings, dict) else {}
        if isinstance(profile, dict):
            techniques.update(_strings(profile.get("covered_techniques")))
        variants = settings.get("configuration_variants", []) if isinstance(settings, dict) else []
        if isinstance(variants, list):
            for variant in variants:
                if isinstance(variant, dict):
                    techniques.update(_strings(variant.get("covered_techniques")))
    return techniques


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
