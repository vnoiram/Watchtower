import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api.app.config import Settings, get_settings
from api.app.database import Base, get_db
from api.app.main import app

TOKENS = "viewer-user:viewer-secret:viewer,operator-user:operator-secret:operator"


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_settings] = lambda: Settings(api_tokens=TOKENS)
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def _repository_payload() -> dict:
    return {
        "provider": "github",
        "owner": "watchtower",
        "name": "demo",
        "source_classification": "public",
    }


def test_missing_token_is_unauthorized(client: TestClient) -> None:
    response = client.get("/v1/repositories")
    assert response.status_code == 401


def test_unknown_token_is_unauthorized(client: TestClient) -> None:
    response = client.get("/v1/repositories", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


def test_viewer_token_can_read(client: TestClient) -> None:
    response = client.get("/v1/repositories", headers={"Authorization": "Bearer viewer-secret"})
    assert response.status_code == 200


def test_viewer_token_cannot_create_repository(client: TestClient) -> None:
    response = client.post(
        "/v1/repositories",
        json=_repository_payload(),
        headers={"Authorization": "Bearer viewer-secret"},
    )
    assert response.status_code == 403


def test_operator_token_can_create_repository_and_is_audited(client: TestClient) -> None:
    response = client.post(
        "/v1/repositories",
        json=_repository_payload(),
        headers={"Authorization": "Bearer operator-secret"},
    )
    assert response.status_code == 200
    assert response.json()["owner"] == "watchtower"

    audit_response = client.get("/v1/audit-logs", headers={"Authorization": "Bearer operator-secret"})
    assert audit_response.status_code == 200
    entries = audit_response.json()["items"]
    assert entries[0]["actor"] == "operator-user"
    assert entries[0]["role"] == "operator"
