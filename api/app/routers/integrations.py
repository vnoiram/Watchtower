import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/github-health", response_model=list[schemas.GitHubIntegrationHealthOut])
def github_integration_health(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    return github_integration_health_items(db, settings)


@router.get("/webhooks", response_model=schemas.CursorPage)
def list_webhook_intake(
    limit: int = 50,
    event: str | None = None,
    status: models.JobStatus | None = None,
    duplicate_candidate: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = webhook_intake_items(db)
    if event:
        items = [item for item in items if item["event"] == event]
    if status:
        items = [item for item in items if item["status"] == status.value]
    if duplicate_candidate is not None:
        items = [item for item in items if item["duplicate_candidate"] is duplicate_candidate]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def github_integration_issue_count(db: Session, settings: Settings) -> int:
    return sum(1 for item in github_integration_health_items(db, settings) if item.status != "ok")


def github_integration_health_items(db: Session, settings: Settings) -> list[schemas.GitHubIntegrationHealthOut]:
    sync_failures = list(
        db.scalars(
            select(models.Job).where(
                models.Job.job_type == models.JobType.repository_sync,
                models.Job.status.in_([models.JobStatus.failed, models.JobStatus.timed_out]),
            )
        )
    )
    issue_actions = _github_issue_error_actions(db)
    error_texts = [job.last_error or "" for job in sync_failures]
    error_texts.extend(_action_error(action) for action in issue_actions)
    return [
        _health(
            "github_auth",
            "ok" if settings.github_token or (settings.github_app_id and settings.github_private_key) else "fail",
            1 if settings.github_token or (settings.github_app_id and settings.github_private_key) else 0,
            "GitHub token or GitHub App credentials are configured",
        ),
        _health(
            "github_webhook_secret",
            "ok" if settings.github_webhook_secret else "warn",
            1 if settings.github_webhook_secret else 0,
            "GitHub webhook signature secret is configured",
        ),
        _health(
            "repository_sync_failures",
            "fail" if sync_failures else "ok",
            len(sync_failures),
            "Repository sync jobs failed or timed out",
        ),
        _health(
            "github_issue_failures",
            "fail" if issue_actions else "ok",
            len(issue_actions),
            "GitHub issue create or close actions failed",
        ),
        _health("github_rate_limit", "warn" if _contains(error_texts, "rate limit", "403") else "ok", _count_matching(error_texts, "rate limit", "403"), "GitHub errors mentioning rate limits"),
        _health("github_timeout", "warn" if _contains(error_texts, "timeout", "timed out") else "ok", _count_matching(error_texts, "timeout", "timed out"), "GitHub errors mentioning timeouts"),
        _health("github_auth_errors", "warn" if _contains(error_texts, "auth", "401", "403", "credential") else "ok", _count_matching(error_texts, "auth", "401", "403", "credential"), "GitHub errors mentioning authentication or authorization"),
    ]


def webhook_intake_items(db: Session) -> list[dict]:
    jobs = list(
        db.scalars(
            select(models.Job)
            .where(models.Job.job_type == models.JobType.repository_sync)
            .order_by(models.Job.created_at.desc(), models.Job.id.asc())
        )
    )
    parsed = [(job, _webhook_context(job)) for job in jobs if _webhook_context(job)[0] or _webhook_context(job)[1]]
    duplicates = _duplicate_webhook_job_ids(parsed)
    return [
        schemas.WebhookIntakeOut(
            job_id=job.id,
            event=event,
            repository=repository,
            status=job.status,
            error=job.last_error,
            duplicate_candidate=job.id in duplicates,
            created_at=job.created_at,
        ).model_dump(mode="json")
        for job, (event, repository) in parsed
    ]


def _github_issue_error_actions(db: Session) -> list[models.RemediationAction]:
    actions = db.scalars(
        select(models.RemediationAction).where(
            models.RemediationAction.provider == "github",
            models.RemediationAction.action_type == "github_issue",
        )
    )
    return [
        action
        for action in actions
        if action.status in {"failed", "close_failed"} or bool(_action_error(action))
    ]


def _action_error(action: models.RemediationAction) -> str:
    metadata = action.metadata_json or {}
    return str(metadata.get("error") or metadata.get("close_error") or "")


def _health(check: str, status: str, count: int, detail: str) -> schemas.GitHubIntegrationHealthOut:
    return schemas.GitHubIntegrationHealthOut(check=check, status=status, count=count, detail=detail)


def _contains(values: list[str], *needles: str) -> bool:
    return _count_matching(values, *needles) > 0


def _count_matching(values: list[str], *needles: str) -> int:
    return sum(1 for value in values if any(needle in value.lower() for needle in needles))


def _webhook_context(job: models.Job) -> tuple[str | None, str | None]:
    payload = job.payload or {}
    event = payload.get("event")
    body = payload.get("body")
    body_payload = _json_body(body)
    repository = None
    if isinstance(body_payload, dict):
        repository_payload = body_payload.get("repository")
        if isinstance(repository_payload, dict):
            repository = repository_payload.get("full_name") or repository_payload.get("name")
        event = event or body_payload.get("event")
    repository = repository or payload.get("repository") or payload.get("repository_id") or payload.get("owner")
    return str(event) if event else None, str(repository) if repository else None


def _json_body(body: object) -> dict | None:
    if isinstance(body, dict):
        return body
    if not isinstance(body, str):
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _duplicate_webhook_job_ids(parsed: list[tuple[models.Job, tuple[str | None, str | None]]]) -> set:
    duplicates = set()
    for index, (job, (event, repository)) in enumerate(parsed):
        if not event or not repository:
            continue
        for other, (other_event, other_repository) in parsed[index + 1 :]:
            if event != other_event or repository != other_repository:
                continue
            if _within(job.created_at, other.created_at, timedelta(minutes=10)):
                duplicates.update({job.id, other.id})
    return duplicates


def _within(left: datetime, right: datetime, window: timedelta) -> bool:
    if left.tzinfo is None and right.tzinfo is not None:
        right = right.replace(tzinfo=None)
    elif left.tzinfo is not None and right.tzinfo is None:
        left = left.replace(tzinfo=None)
    return abs(left - right) <= window
