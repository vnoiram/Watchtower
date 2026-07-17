import secrets
from dataclasses import dataclass

from fastapi import Depends, Header

from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.errors import problem


@dataclass(frozen=True)
class Principal:
    actor: str
    role: str


ROLE_ORDER = {"viewer": 1, "operator": 2, "admin": 3}


def _extract_bearer_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[len("Bearer ") :]
    return token or None


def get_principal(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> Principal:
    token = _extract_bearer_token(authorization)
    if not token:
        raise problem(401, "Unauthorized", "Missing or invalid bearer token")

    tokens = settings.parsed_api_tokens()
    if tokens:
        for candidate, (actor, role) in tokens.items():
            if secrets.compare_digest(token, candidate):
                return Principal(actor=actor, role=role)
        raise problem(401, "Unauthorized", "Missing or invalid bearer token")

    if secrets.compare_digest(token, settings.api_token):
        return Principal(actor="api-token", role=settings.api_default_role)
    raise problem(401, "Unauthorized", "Missing or invalid bearer token")


def require_role(required: str):
    def dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if ROLE_ORDER.get(principal.role, 0) < ROLE_ORDER[required]:
            raise problem(403, "Forbidden", f"Requires {required} role")
        return principal

    return dependency


DbSession = Depends(get_db)
