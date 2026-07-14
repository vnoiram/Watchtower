import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from jose import jwt

from api.app.config import Settings
from api.app.models import Repository

GITHUB_API_VERSION = "2022-11-28"
GITHUB_ACCEPT_HEADER = "application/vnd.github+json"
GITHUB_REPOSITORY_INSTALLATION_API = "https://api.github.com/repos/{owner}/{name}/installation"
GITHUB_INSTALLATION_TOKEN_API = "https://api.github.com/app/installations/{installation_id}/access_tokens"


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


def github_api_headers(token: str) -> dict[str, str]:
    return {
        "Accept": GITHUB_ACCEPT_HEADER,
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def github_app_configured(settings: Settings) -> bool:
    return bool(settings.github_app_id and settings.github_private_key)


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
