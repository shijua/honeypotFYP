from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from services.binding_service.app import app
from services.binding_service.app import get_service
from services.binding_service.domain import BindingService
from services.binding_service.repository import InMemoryBindingRepository


@pytest.fixture
def binding_client() -> TestClient:
    repository = InMemoryBindingRepository()
    service = BindingService(repository)

    def _get_service() -> BindingService:
        return service

    app.dependency_overrides.clear()
    # Replace dependency provider directly for test isolation.
    app.dependency_overrides[get_service] = _get_service
    client = TestClient(app)
    try:
        yield client
    finally:
        app.dependency_overrides.clear()
