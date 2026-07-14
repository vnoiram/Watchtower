import hashlib
import hmac
from dataclasses import dataclass


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

