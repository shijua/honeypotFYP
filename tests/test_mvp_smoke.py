from __future__ import annotations

import pytest

from libs.contracts.models import (
    ControllerTickRequest,
    EvidenceIngestRequest,
    FalcoEvent,
    OrchestratorApplyRequest,
    ResolveBindingRequest,
)
from services.binding_service.domain import BindingService
from services.controller.domain import ControllerService
from services.gateway.domain import GatewayService
from services.orchestrator.domain import OrchestratorService
from services.profiler.domain import ProfilerService
from tests.support.attack_catalog import build_test_attack_catalog
from tests.support.inmemory_repositories import (
    InMemoryAssetRepository,
    InMemoryBindingRepository,
    InMemoryEvidenceRepository,
    InMemoryGatewayRouteRepository,
    InMemoryProfileRepository,
    InMemoryTechniquePriorRepository,
)


pytestmark = pytest.mark.e2e_smoke


def test_mvp_closes_the_loop_from_binding_to_unlock() -> None:
    binding_service = BindingService(InMemoryBindingRepository())
    profiler_service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    controller_service = ControllerService(
        InMemoryAssetRepository(),
        InMemoryTechniquePriorRepository(),
    )
    orchestrator_service = OrchestratorService(binding_service, gateway_service)
    attacker_key = "203.0.113.200"

    binding = binding_service.resolve(
        ResolveBindingRequest(attacker_key=attacker_key, protocol="ssh")
    )

    profiler_service.ingest(
        EvidenceIngestRequest(
            attacker_key=attacker_key,
            binding_id=binding.binding_id,
            event=FalcoEvent(
                ts="2026-01-01T00:00:00Z",
                falco_rule="Read sensitive file",
                priority="WARNING",
                output="Sensitive file read /etc/shadow",
                tags=["mitre_credential_access", "T1003"],
                output_fields={"proc_cmdline": "cat /etc/shadow"},
            ),
        )
    )
    profile = profiler_service.get_profile(attacker_key)

    first_tick = controller_service.tick(
        ControllerTickRequest(
            attacker_key=attacker_key,
            binding_id=binding.binding_id,
            profile=profile,
            unlocked_asset_ids=[],
        )
    )

    first_apply = orchestrator_service.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=first_tick.actions,
        )
    )
    assert first_apply.binding.unlocked_assets == ["internal-portal"]
    gateway_state = gateway_service.get_state(binding.binding_id)
    assert gateway_state.exposed_assets == ["internal-portal"]

    profiler_service.ingest(
        EvidenceIngestRequest(
            attacker_key=attacker_key,
            binding_id=binding.binding_id,
            event=FalcoEvent(
                ts="2026-01-01T00:00:05Z",
                falco_rule="HTTP honeypot request",
                priority="WARNING",
                output="HTTP GET /backup/db_backup_2024.sql.bak matched public_http_credential_discovery",
                tags=["mitre_credential_access", "T1552.001"],
                output_fields={
                    "source": "public_http",
                    "http_method": "GET",
                    "http_path": "/backup/db_backup_2024.sql.bak",
                    "http_rule_names": ["public_http_credential_discovery"],
                    "http_indicators": ["path:.bak"],
                },
            ),
        )
    )
    updated_profile = profiler_service.get_profile(attacker_key)

    second_tick = controller_service.tick(
        ControllerTickRequest(
            attacker_key=attacker_key,
            binding_id=binding.binding_id,
            profile=updated_profile,
            unlocked_asset_ids=["internal-portal"],
        )
    )

    second_apply = orchestrator_service.apply(
        OrchestratorApplyRequest(
            binding_id=binding.binding_id,
            actions=second_tick.actions,
        )
    )
    assert "finance-share" in second_apply.binding.unlocked_assets
    final_gateway_state = gateway_service.get_state(binding.binding_id)
    assert "finance-share" in final_gateway_state.exposed_assets
