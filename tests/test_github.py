import hashlib
import hmac
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.database import Base
from api.app.models import Repository, RepositoryProvider, SourceClassification
from api.app.services.github import (
    GitHubRepositoryInfo,
    GitHubAuthError,
    create_github_app_jwt,
    get_repository_installation_token,
    list_github_owner_repositories,
    verify_webhook_signature,
)
from api.app.services.repositories import sync_github_repositories


def test_verify_webhook_signature() -> None:
    body = b'{"zen":"ok"}'
    secret = "secret"
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_webhook_signature(secret, body, signature)
    assert not verify_webhook_signature(secret, body, "sha256=bad")


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: dict | list | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self) -> dict | list:
        return self._payload


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


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


def github_repo_payload(
    *,
    repo_id: int = 123,
    owner: str = "acme",
    name: str = "demo",
    visibility: str = "private",
) -> dict:
    return {
        "id": repo_id,
        "owner": {"login": owner},
        "name": name,
        "html_url": f"https://github.com/{owner}/{name}",
        "visibility": visibility,
        "default_branch": "main",
        "archived": False,
        "fork": False,
        "topics": ["python"],
        "language": "Python",
        "pushed_at": "2026-07-14T12:34:56Z",
    }


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


def test_list_github_owner_repositories_fetches_org_repos(monkeypatch) -> None:
    calls = []

    def fake_get(url: str, **kwargs) -> FakeResponse:
        calls.append((url, kwargs))
        return FakeResponse(200, [github_repo_payload()])

    monkeypatch.setattr("api.app.services.github.httpx.get", fake_get)

    repositories = list_github_owner_repositories("acme", Settings(github_token="token"))

    assert calls[0][0] == "https://api.github.com/orgs/acme/repos?per_page=100&type=all"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer token"
    assert repositories == [
        GitHubRepositoryInfo(
            provider_repository_id="123",
            owner="acme",
            name="demo",
            url="https://github.com/acme/demo",
            visibility="private",
            default_branch="main",
            archived=False,
            fork=False,
            topics=["python"],
            primary_language="Python",
            pushed_at=datetime(2026, 7, 14, 12, 34, 56, tzinfo=timezone.utc),
        )
    ]


def test_list_github_owner_repositories_falls_back_to_user_repos_on_org_404(monkeypatch) -> None:
    calls = []

    def fake_get(url: str, **kwargs) -> FakeResponse:
        calls.append(url)
        if "/orgs/" in url:
            return FakeResponse(404, text="not found")
        return FakeResponse(200, [github_repo_payload(owner="octocat")])

    monkeypatch.setattr("api.app.services.github.httpx.get", fake_get)

    repositories = list_github_owner_repositories("octocat", Settings(github_token="token"))

    assert calls == [
        "https://api.github.com/orgs/octocat/repos?per_page=100&type=all",
        "https://api.github.com/users/octocat/repos?per_page=100&type=all",
    ]
    assert repositories[0].owner == "octocat"


def test_list_github_owner_repositories_follows_pagination(monkeypatch) -> None:
    calls = []

    def fake_get(url: str, **kwargs) -> FakeResponse:
        calls.append(url)
        if "page=2" in url:
            return FakeResponse(200, [github_repo_payload(repo_id=2, name="second")])
        return FakeResponse(
            200,
            [github_repo_payload(repo_id=1, name="first")],
            headers={"Link": '<https://api.github.com/orgs/acme/repos?per_page=100&type=all&page=2>; rel="next"'},
        )

    monkeypatch.setattr("api.app.services.github.httpx.get", fake_get)

    repositories = list_github_owner_repositories("acme", Settings(github_token="token"))

    assert calls == [
        "https://api.github.com/orgs/acme/repos?per_page=100&type=all",
        "https://api.github.com/orgs/acme/repos?per_page=100&type=all&page=2",
    ]
    assert [repository.name for repository in repositories] == ["first", "second"]


def test_list_github_owner_repositories_requires_token() -> None:
    with pytest.raises(GitHubAuthError, match="github_token is not configured for repository sync"):
        list_github_owner_repositories("acme", Settings())


def test_list_github_owner_repositories_rejects_non_success(monkeypatch) -> None:
    monkeypatch.setattr(
        "api.app.services.github.httpx.get",
        lambda *_, **__: FakeResponse(403, text="forbidden"),
    )

    with pytest.raises(GitHubAuthError, match="repositories request failed with status 403"):
        list_github_owner_repositories("acme", Settings(github_token="token"))


def test_list_github_owner_repositories_rejects_invalid_response(monkeypatch) -> None:
    monkeypatch.setattr(
        "api.app.services.github.httpx.get",
        lambda *_, **__: FakeResponse(200, {"id": 1}),
    )

    with pytest.raises(GitHubAuthError, match="repositories response must be an array"):
        list_github_owner_repositories("acme", Settings(github_token="token"))


def test_sync_github_repositories_creates_new_repo(monkeypatch) -> None:
    SessionLocal = session_factory()
    repo_info = GitHubRepositoryInfo(
        provider_repository_id="123",
        owner="acme",
        name="demo",
        url="https://github.com/acme/demo",
        visibility="public",
        default_branch="main",
        archived=False,
        fork=False,
        topics=["python"],
        primary_language="Python",
        pushed_at=datetime(2026, 7, 14, 12, 34, 56, tzinfo=timezone.utc),
    )
    monkeypatch.setattr("api.app.services.repositories.list_github_owner_repositories", lambda *_: [repo_info])

    with SessionLocal() as db:
        repositories = sync_github_repositories(db, "acme", Settings(github_token="token"))
        db.flush()

        repository = repositories[0]
        assert repository.provider == RepositoryProvider.github
        assert repository.provider_repository_id == "123"
        assert repository.owner == "acme"
        assert repository.name == "demo"
        assert repository.url == "https://github.com/acme/demo"
        assert repository.visibility == "public"
        assert repository.default_branch == "main"
        assert repository.topics == ["python"]
        assert repository.primary_language == "Python"
        assert repository.pushed_at == datetime(2026, 7, 14, 12, 34, 56, tzinfo=timezone.utc)
        assert repository.last_synced_at is not None
        assert repository.source_classification == SourceClassification.public


def test_sync_github_repositories_updates_by_provider_repository_id(monkeypatch) -> None:
    SessionLocal = session_factory()
    repo_info = GitHubRepositoryInfo(
        provider_repository_id="123",
        owner="acme",
        name="renamed",
        url="https://github.com/acme/renamed",
        visibility="private",
        default_branch="trunk",
        archived=True,
        fork=True,
        topics=["security"],
        primary_language="Go",
    )
    monkeypatch.setattr("api.app.services.repositories.list_github_owner_repositories", lambda *_: [repo_info])

    with SessionLocal() as db:
        existing = Repository(
            provider=RepositoryProvider.github,
            provider_repository_id="123",
            owner="acme",
            name="demo",
            source_classification=SourceClassification.public,
            archived=False,
            fork=False,
            topics=[],
        )
        db.add(existing)
        db.flush()

        repositories = sync_github_repositories(db, "acme", Settings(github_token="token"))
        db.flush()

        assert repositories == [existing]
        assert db.scalars(select(Repository)).all() == [existing]
        assert existing.name == "renamed"
        assert existing.visibility == "private"
        assert existing.source_classification == SourceClassification.private


def test_sync_github_repositories_updates_existing_owner_name_with_provider_id(monkeypatch) -> None:
    SessionLocal = session_factory()
    repo_info = GitHubRepositoryInfo(
        provider_repository_id="123",
        owner="acme",
        name="demo",
        url="https://github.com/acme/demo",
        visibility="public",
        default_branch="main",
        archived=False,
        fork=False,
        topics=[],
        primary_language=None,
    )
    monkeypatch.setattr("api.app.services.repositories.list_github_owner_repositories", lambda *_: [repo_info])

    with SessionLocal() as db:
        existing = Repository(
            provider=RepositoryProvider.github,
            provider_repository_id=None,
            owner="acme",
            name="demo",
            source_classification=SourceClassification.private,
            archived=False,
            fork=False,
            topics=[],
        )
        db.add(existing)
        db.flush()

        repositories = sync_github_repositories(db, "acme", Settings(github_token="token"))
        db.flush()

        assert repositories == [existing]
        assert existing.provider_repository_id == "123"
        assert existing.source_classification == SourceClassification.public
