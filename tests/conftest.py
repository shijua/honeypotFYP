from __future__ import annotations

import random

import pytest
from fastapi.testclient import TestClient

from libs.common.config import RuntimeConfig
from services.binding_service.app import app as binding_app
from services.binding_service.app import get_service as get_binding_service
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository
from services.controller.app import app as controller_app
from services.controller.app import get_service as get_controller_service
from services.controller.domain import ControllerService
from services.controller.repository import InMemoryAssetRepository, InMemoryTransitionRepository
from services.gateway.app import app as gateway_app
from services.gateway.app import get_service as get_gateway_service
from services.gateway.domain import GatewayService
from services.gateway.repository import InMemoryGatewayRouteRepository
from services.orchestrator.app import app as orchestrator_app
from services.orchestrator.app import get_service as get_orchestrator_service
from services.orchestrator.domain import OrchestratorService
from services.profiler.app import app as profiler_app
from services.profiler.app import get_service as get_profiler_service
from services.profiler.domain import ProfilerService
from services.profiler.repository import InMemoryEvidenceRepository, InMemoryProfileRepository
from tests.support.attack_catalog import build_test_attack_catalog


@pytest.fixture
def binding_client() -> TestClient:
    repository = InMemoryBindingRepository()
    service = BindingService(repository)

    def _get_service() -> BindingService:
        return service

    binding_app.dependency_overrides.clear()
    # Replace dependency provider directly for test isolation.
    binding_app.dependency_overrides[get_binding_service] = _get_service
    client = TestClient(binding_app)
    try:
        yield client
    finally:
        binding_app.dependency_overrides.clear()


@pytest.fixture
def profiler_client() -> TestClient:
    evidence_repository = InMemoryEvidenceRepository()
    profile_repository = InMemoryProfileRepository()
    service = ProfilerService(
        evidence_repository,
        profile_repository,
        build_test_attack_catalog(),
    )

    def _get_service() -> ProfilerService:
        return service

    profiler_app.dependency_overrides.clear()
    profiler_app.dependency_overrides[get_profiler_service] = _get_service
    client = TestClient(profiler_app)
    try:
        yield client
    finally:
        profiler_app.dependency_overrides.clear()


@pytest.fixture
def controller_client() -> TestClient:
    service = ControllerService(
        InMemoryAssetRepository(),
        InMemoryTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )

    def _get_service() -> ControllerService:
        return service

    controller_app.dependency_overrides.clear()
    controller_app.dependency_overrides[get_controller_service] = _get_service
    client = TestClient(controller_app)
    try:
        yield client
    finally:
        controller_app.dependency_overrides.clear()


@pytest.fixture
def gateway_client() -> TestClient:
    service = GatewayService(InMemoryGatewayRouteRepository())

    def _get_service() -> GatewayService:
        return service

    gateway_app.dependency_overrides.clear()
    gateway_app.dependency_overrides[get_gateway_service] = _get_service
    client = TestClient(gateway_app)
    try:
        yield client
    finally:
        gateway_app.dependency_overrides.clear()


@pytest.fixture
def mvp_clients() -> dict[str, TestClient]:
    binding_repository = InMemoryBindingRepository()
    binding_service = BindingService(binding_repository)
    profiler_service = ProfilerService(
        InMemoryEvidenceRepository(),
        InMemoryProfileRepository(),
        build_test_attack_catalog(),
    )
    controller_service = ControllerService(
        InMemoryAssetRepository(),
        InMemoryTransitionRepository(),
        config=RuntimeConfig(epsilon=0.0),
        rng=random.Random(0),
    )
    gateway_service = GatewayService(InMemoryGatewayRouteRepository())
    orchestrator_service = OrchestratorService(
        binding_service,
        gateway_service,
    )

    binding_app.dependency_overrides.clear()
    profiler_app.dependency_overrides.clear()
    controller_app.dependency_overrides.clear()
    orchestrator_app.dependency_overrides.clear()
    gateway_app.dependency_overrides.clear()

    binding_app.dependency_overrides[get_binding_service] = lambda: binding_service
    profiler_app.dependency_overrides[get_profiler_service] = lambda: profiler_service
    controller_app.dependency_overrides[get_controller_service] = lambda: controller_service
    orchestrator_app.dependency_overrides[get_orchestrator_service] = (
        lambda: orchestrator_service
    )
    gateway_app.dependency_overrides[get_gateway_service] = lambda: gateway_service

    clients = {
        "binding": TestClient(binding_app),
        "profiler": TestClient(profiler_app),
        "controller": TestClient(controller_app),
        "orchestrator": TestClient(orchestrator_app),
        "gateway": TestClient(gateway_app),
    }
    try:
        yield clients
    finally:
        binding_app.dependency_overrides.clear()
        profiler_app.dependency_overrides.clear()
        controller_app.dependency_overrides.clear()
        orchestrator_app.dependency_overrides.clear()
        gateway_app.dependency_overrides.clear()
