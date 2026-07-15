from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/repository-sync", tags=["repository-sync"])


@router.get("", response_model=schemas.CursorPage)
def list_repository_sync(
    limit: int = 50,
    stale: bool | None = None,
    provider: models.RepositoryProvider | None = None,
    source_classification: models.SourceClassification | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc())
    if provider:
        stmt = stmt.where(models.Repository.provider == provider)
    if source_classification:
        stmt = stmt.where(models.Repository.source_classification == source_classification)
    sync_jobs = _latest_sync_jobs(db)
    items = []
    for repository in db.execute(stmt).scalars():
        job = sync_jobs.get(repository.id)
        reasons = _sync_reasons(repository, job, cutoff)
        is_stale = bool(reasons)
        if stale is not None and is_stale is not stale:
            continue
        items.append(
            schemas.RepositorySyncOut(
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                provider=repository.provider,
                source_classification=repository.source_classification,
                archived=repository.archived,
                fork=repository.fork,
                last_synced_at=repository.last_synced_at,
                latest_sync_job_id=job.id if job else None,
                latest_sync_job_status=job.status if job else None,
                latest_sync_job_error=job.last_error if job else None,
                stale=is_stale,
                reasons=reasons,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/lag", response_model=schemas.CursorPage)
def list_repository_sync_lag(
    limit: int = 50,
    lag_type: str | None = None,
    provider: models.RepositoryProvider | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = repository_sync_lag_items(db)
    if lag_type:
        items = [item for item in items if item["lag_type"] == lag_type]
    if provider:
        items = [item for item in items if item["provider"] == provider.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def repository_sync_lag_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    items = []
    repositories = db.scalars(select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc()))
    for repository in repositories:
        latest_scan = _latest_repository_scan(db, repository.id)
        context = (repository, latest_scan)
        if repository.last_synced_at is None:
            items.append(_lag_item("never_synced", *context, detail="Repository has no sync timestamp"))
        elif repository.last_synced_at < _matching_datetime(cutoff, repository.last_synced_at):
            items.append(_lag_item("stale_sync", *context, detail="Repository sync is older than 30 days"))
        if repository.pushed_at and repository.last_synced_at and repository.pushed_at > _matching_datetime(repository.last_synced_at, repository.pushed_at):
            items.append(_lag_item("pushed_after_sync", *context, detail="Repository push is newer than last sync"))
        if repository.pushed_at and latest_scan and repository.pushed_at > _matching_datetime(latest_scan.created_at, repository.pushed_at):
            items.append(_lag_item("pushed_after_scan", *context, detail="Repository push is newer than latest scan"))
        if repository.provider == models.RepositoryProvider.github and not repository.provider_repository_id:
            items.append(_lag_item("missing_provider_repository_id", *context, detail="GitHub repository has no provider_repository_id"))
    return items


def _latest_sync_jobs(db: Session) -> dict:
    jobs = db.execute(
        select(models.Job)
        .where(models.Job.job_type == models.JobType.repository_sync)
        .order_by(models.Job.repository_id.asc(), models.Job.created_at.desc(), models.Job.id.desc())
    ).scalars()
    by_repository = {}
    for job in jobs:
        if job.repository_id:
            by_repository.setdefault(job.repository_id, job)
    return by_repository


def _sync_reasons(repository: models.Repository, job: models.Job | None, cutoff: datetime) -> list[str]:
    reasons = []
    if repository.last_synced_at is None:
        reasons.append("never_synced")
    elif repository.last_synced_at < _matching_datetime(cutoff, repository.last_synced_at):
        reasons.append("stale_sync")
    if job and job.status in {models.JobStatus.failed, models.JobStatus.cancelled, models.JobStatus.timed_out}:
        reasons.append("sync_job_failed")
    if repository.archived:
        reasons.append("archived")
    if repository.fork:
        reasons.append("fork")
    return reasons


def _latest_repository_scan(db: Session, repository_id) -> models.Scan | None:
    return db.scalar(
        select(models.Scan)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .where(models.Application.repository_id == repository_id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
    )


def _lag_item(
    lag_type: str,
    repository: models.Repository,
    latest_scan: models.Scan | None,
    detail: str,
) -> dict:
    return schemas.RepositorySyncLagOut(
        lag_type=lag_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        provider=repository.provider,
        last_synced_at=repository.last_synced_at,
        pushed_at=repository.pushed_at,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        detail=detail,
    ).model_dump(mode="json")


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
