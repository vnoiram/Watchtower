import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from jose import jwt

from api.app.config import Settings
from api.app.models import Repository

GITHUB_API_VERSION = "2022-11-28"
GITHUB_ACCEPT_HEADER = "application/vnd.github+json"
GITHUB_REPOSITORY_INSTALLATION_API = "https://api.github.com/repos/{owner}/{name}/installation"
GITHUB_INSTALLATION_TOKEN_API = "https://api.github.com/app/installations/{installation_id}/access_tokens"
GITHUB_ORG_REPOSITORIES_API = "https://api.github.com/orgs/{owner}/repos?per_page=100&type=all"
GITHUB_USER_REPOSITORIES_API = "https://api.github.com/users/{owner}/repos?per_page=100&type=all"


class GitHubAuthError(RuntimeError):
    pass


def verify_webhook_signature(secret: str, body: bytes, signature_header: str | None) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@dataclass(frozen=True)
class GitHubRepositoryInfo:
    provider_repository_id: str
    owner: str
    name: str
    url: str
    visibility: str
    default_branch: str
    archived: bool
    fork: bool
    topics: list[str]
    primary_language: str | None
    pushed_at: datetime | None = None


def github_api_headers(token: str) -> dict[str, str]:
    return {
        "Accept": GITHUB_ACCEPT_HEADER,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def github_app_configured(settings: Settings) -> bool:
    return bool(settings.github_app_id and settings.github_private_key)


def _next_link(response: httpx.Response) -> str | None:
    for link in response.headers.get("Link", "").split(","):
        url_part, _, rel_part = link.strip().partition(";")
        if 'rel="next"' not in rel_part:
            continue
        url = url_part.strip()
        if url.startswith("<") and url.endswith(">"):
            return url[1:-1]
    return None


def _parse_github_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if not isinstance(value, str):
        raise GitHubAuthError("github repository response has invalid pushed_at")
    normalized = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        try:
            return parsedate_to_datetime(value)
        except (TypeError, ValueError) as exc:
            raise GitHubAuthError("github repository response has invalid pushed_at") from exc


def _normalize_github_repository(payload: Any) -> GitHubRepositoryInfo:
    if not isinstance(payload, dict):
        raise GitHubAuthError("github repository response item must be an object")

    owner_payload = payload.get("owner")
    owner_login = owner_payload.get("login") if isinstance(owner_payload, dict) else None
    repo_id = payload.get("id")
    name = payload.get("name")
    url = payload.get("html_url") or payload.get("url")
    visibility = payload.get("visibility")
    default_branch = payload.get("default_branch")
    topics = payload.get("topics") or []
    if (
        repo_id is None
        or not owner_login
        or not name
        or not url
        or not visibility
        or not default_branch
        or not isinstance(topics, list)
    ):
        raise GitHubAuthError("github repository response is missing required fields")

    return GitHubRepositoryInfo(
        provider_repository_id=str(repo_id),
        owner=str(owner_login),
        name=str(name),
        url=str(url),
        visibility=str(visibility),
        default_branch=str(default_branch),
        archived=bool(payload.get("archived")),
        fork=bool(payload.get("fork")),
        topics=[str(topic) for topic in topics],
        primary_language=str(payload["language"]) if payload.get("language") is not None else None,
        pushed_at=_parse_github_datetime(payload.get("pushed_at")),
    )


def _get_github_json(url: str, token: str, timeout_seconds: float) -> httpx.Response:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com":
        raise GitHubAuthError("github pagination returned an unexpected URL")
    return httpx.get(
        url,
        headers=github_api_headers(token),
        timeout=timeout_seconds,
    )


def list_github_owner_repositories(
    owner: str,
    settings: Settings,
    *,
    timeout_seconds: float = 10.0,
) -> list[GitHubRepositoryInfo]:
    if not settings.github_token:
        raise GitHubAuthError("github_token is not configured for repository sync")

    token = settings.github_token
    url = GITHUB_ORG_REPOSITORIES_API.format(owner=owner)
    repositories: list[GitHubRepositoryInfo] = []
    tried_user_fallback = False
    while url:
        response = _get_github_json(url, token, timeout_seconds)
        if response.status_code == 404 and not tried_user_fallback and "/orgs/" in url:
            url = GITHUB_USER_REPOSITORIES_API.format(owner=owner)
            tried_user_fallback = True
            continue
        if response.status_code < 200 or response.status_code >= 300:
            raise GitHubAuthError(
                f"github repositories request failed with status {response.status_code}: {response.text}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise GitHubAuthError("github repositories response is not valid JSON") from exc
        if not isinstance(payload, list):
            raise GitHubAuthError("github repositories response must be an array")
        repositories.extend(_normalize_github_repository(repo) for repo in payload)
        url = _next_link(response)

    return repositories


def create_github_app_jwt(settings: Settings) -> str:
    if not settings.github_app_id:
        raise GitHubAuthError("github_app_id is not configured")
    if not settings.github_private_key:
        raise GitHubAuthError("github_private_key is not configured")

    now = datetime.now(timezone.utc)
    payload = {
        "iat": int((now - timedelta(seconds=60)).timestamp()),
        "exp": int((now + timedelta(minutes=9)).timestamp()),
        "iss": settings.github_app_id,
    }
    private_key = settings.github_private_key.replace("\\n", "\n")
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as exc:  # noqa: BLE001
        raise GitHubAuthError(f"failed to create GitHub App JWT: {exc}") from exc


def get_repository_installation_token(
    repository: Repository,
    settings: Settings,
    *,
    timeout_seconds: float = 10.0,
) -> str:
    app_jwt = create_github_app_jwt(settings)
    installation_url = GITHUB_REPOSITORY_INSTALLATION_API.format(
        owner=repository.owner,
        name=repository.name,
    )
    installation_response = httpx.get(
        installation_url,
        headers=github_api_headers(app_jwt),
        timeout=timeout_seconds,
    )
    if installation_response.status_code < 200 or installation_response.status_code >= 300:
        raise GitHubAuthError(
            "github installation lookup failed with status "
            f"{installation_response.status_code}: {installation_response.text}"
        )

    installation_payload = installation_response.json()
    installation_id = installation_payload.get("id")
    if installation_id is None:
        raise GitHubAuthError("github installation lookup response is missing id")

    token_url = GITHUB_INSTALLATION_TOKEN_API.format(installation_id=installation_id)
    token_response = httpx.post(
        token_url,
        headers=github_api_headers(app_jwt),
        timeout=timeout_seconds,
    )
    if token_response.status_code < 200 or token_response.status_code >= 300:
        raise GitHubAuthError(
            "github installation token request failed with status "
            f"{token_response.status_code}: {token_response.text}"
        )

    token_payload = token_response.json()
    token = token_payload.get("token")
    if not token:
        raise GitHubAuthError("github installation token response is missing token")
    return str(token)
