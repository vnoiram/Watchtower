import hashlib
import hmac

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from api.app.config import Settings
from api.app.models import Repository, RepositoryProvider, SourceClassification
from api.app.services.github import (
    GitHubAuthError,
    create_github_app_jwt,
    get_repository_installation_token,
    verify_webhook_signature,
)


def test_verify_webhook_signature() -> None:
    body = b'{"zen":"ok"}'
    secret = "secret"
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(secret, body, signature)
    assert not verify_webhook_signature(secret, body, "sha256=bad")


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self) -> dict:
        return self._payload


def private_key_pem() -> str:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def github_repo() -> Repository:
    return Repository(
        provider=RepositoryProvider.github,
        provider_repository_id="repo-1",
        owner="local",
        name="demo",
        url="https://github.com/local/demo",
        source_classification=SourceClassification.private,
        archived=False,
        fork=False,
        topics=[],
    )


def test_create_github_app_jwt() -> None:
    token = create_github_app_jwt(
        Settings(github_app_id="12345", github_private_key=private_key_pem())
    )

    claims = jwt.get_unverified_claims(token)

    assert claims["iss"] == "12345"
    assert claims["exp"] > claims["iat"]


def test_create_github_app_jwt_requires_settings() -> None:
    with pytest.raises(GitHubAuthError, match="github_app_id is not configured"):
        create_github_app_jwt(Settings(github_private_key=private_key_pem()))

    with pytest.raises(GitHubAuthError, match="github_private_key is not configured"):
        create_github_app_jwt(Settings(github_app_id="12345"))


def test_create_github_app_jwt_rejects_invalid_key() -> None:
    with pytest.raises(GitHubAuthError, match="failed to create GitHub App JWT"):
        create_github_app_jwt(Settings(github_app_id="12345", github_private_key="bad-key"))


def test_get_repository_installation_token(monkeypatch) -> None:
    calls = []

    def fake_get(url: str, **kwargs) -> FakeResponse:
        calls.append(("GET", url, kwargs))
        return FakeResponse(200, {"id": 99})

    def fake_post(url: str, **kwargs) -> FakeResponse:
        calls.append(("POST", url, kwargs))
        return FakeResponse(201, {"token": "installation-token"})

    monkeypatch.setattr("api.app.services.github.httpx.get", fake_get)
    monkeypatch.setattr("api.app.services.github.httpx.post", fake_post)

    token = get_repository_installation_token(
        github_repo(),
        Settings(github_app_id="12345", github_private_key=private_key_pem()),
    )

    assert token == "installation-token"
    assert calls[0][0] == "GET"
    assert calls[0][1] == "https://api.github.com/repos/local/demo/installation"
    assert calls[1][0] == "POST"
    assert calls[1][1] == "https://api.github.com/app/installations/99/access_tokens"
    assert calls[0][2]["headers"]["Authorization"].startswith("Bearer ")
    assert calls[1][2]["headers"]["Authorization"].startswith("Bearer ")


def test_get_repository_installation_token_records_lookup_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "api.app.services.github.httpx.get",
        lambda *_, **__: FakeResponse(404, text="not found"),
    )

    with pytest.raises(GitHubAuthError, match="installation lookup failed with status 404"):
        get_repository_installation_token(
            github_repo(),
            Settings(github_app_id="12345", github_private_key=private_key_pem()),
        )


def test_get_repository_installation_token_records_token_failure(monkeypatch) -> None:
    monkeypatch.setattr(
        "api.app.services.github.httpx.get",
        lambda *_, **__: FakeResponse(200, {"id": 99}),
    )
    monkeypatch.setattr(
        "api.app.services.github.httpx.post",
        lambda *_, **__: FakeResponse(403, text="forbidden"),
    )

    with pytest.raises(GitHubAuthError, match="installation token request failed with status 403"):
        get_repository_installation_token(
            github_repo(),
            Settings(github_app_id="12345", github_private_key=private_key_pem()),
        )


def test_get_repository_installation_token_requires_token_in_response(monkeypatch) -> None:
    monkeypatch.setattr(
        "api.app.services.github.httpx.get",
        lambda *_, **__: FakeResponse(200, {"id": 99}),
    )
    monkeypatch.setattr(
        "api.app.services.github.httpx.post",
        lambda *_, **__: FakeResponse(201, {}),
    )

    with pytest.raises(GitHubAuthError, match="installation token response is missing token"):
        get_repository_installation_token(
            github_repo(),
            Settings(github_app_id="12345", github_private_key=private_key_pem()),
        )
