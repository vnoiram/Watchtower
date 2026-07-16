import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.pagination import apply_cursor, encode_cursor
from api.app.services.audit import audit
from api.app.services.jobs import enqueue_job

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.post("", response_model=schemas.JobOut)
def create_job(
    payload: schemas.JobCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    job = enqueue_job(db, **payload.model_dump())
    audit(db, principal.actor, principal.role, "job.create", "job", str(job.id))
    db.commit()
    db.refresh(job)
    return job


@router.get("", response_model=schemas.CursorPage)
def list_jobs(
    cursor: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = apply_cursor(select(models.Job), models.Job, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.JobOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)


@router.get("/retry-candidates", response_model=schemas.CursorPage)
def list_retry_candidates(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Job)
        .where(
            models.Job.status.in_(
                [
                    models.JobStatus.failed,
                    models.JobStatus.timed_out,
                    models.JobStatus.cancelled,
                ]
            ),
            models.Job.attempts < models.Job.max_attempts,
        )
        .order_by(models.Job.created_at.desc(), models.Job.id.asc())
        .limit(min(limit, 100))
    )
    items = []
    for job in db.execute(stmt).scalars():
        repository = db.get(models.Repository, job.repository_id) if job.repository_id else None
        application = db.get(models.Application, job.application_id) if job.application_id else None
        items.append(
            schemas.JobRetryCandidateOut(
                id=job.id,
                job_type=job.job_type,
                status=job.status,
                repository_id=job.repository_id,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                application_id=job.application_id,
                application_name=application.name if application else None,
                attempts=job.attempts,
                max_attempts=job.max_attempts,
                run_after=job.run_after,
                last_error=job.last_error,
                created_at=job.created_at,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/backlog", response_model=schemas.CursorPage)
def list_job_backlog(
    limit: int = 50,
    job_type: models.JobType | None = None,
    status: models.JobStatus | None = None,
    reason: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = job_backlog_items(db)
    if job_type:
        items = [item for item in items if item["job_type"] == job_type.value]
    if status:
        items = [item for item in items if item["status"] == status.value]
    if reason:
        items = [item for item in items if item["reason"] == reason]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/concurrency-risks", response_model=schemas.CursorPage)
def list_job_concurrency_risks(
    limit: int = 50,
    risk_type: str | None = None,
    job_type: models.JobType | None = None,
    status: models.JobStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = job_concurrency_risk_items(db)
    if risk_type:
        items = [item for item in items if item["risk_type"] == risk_type]
    if job_type:
        items = [item for item in items if item["job_type"] == job_type.value]
    if status:
        items = [item for item in items if item["status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/retry-posture", response_model=schemas.CursorPage)
def list_job_retry_posture(
    limit: int = 50,
    gap_type: str | None = None,
    job_type: models.JobType | None = None,
    status: models.JobStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = job_retry_posture_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if job_type:
        items = [item for item in items if item["job_type"] == job_type.value]
    if status:
        items = [item for item in items if item["status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def job_retry_gap_count(db: Session) -> int:
    return len(job_retry_posture_items(db))


def job_concurrency_risk_count(db: Session) -> int:
    return len(job_concurrency_risk_items(db))


def job_retry_posture_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    repositories = {repo.id: repo for repo in db.scalars(select(models.Repository))}
    applications = {app.id: app for app in db.scalars(select(models.Application))}
    stmt = (
        select(models.Job)
        .where(
            models.Job.status.in_(
                [
                    models.JobStatus.queued,
                    models.JobStatus.running,
                    models.JobStatus.failed,
                    models.JobStatus.timed_out,
                    models.JobStatus.cancelled,
                ]
            )
        )
        .order_by(models.Job.created_at.asc(), models.Job.id.asc())
    )
    items = []
    for job in db.scalars(stmt):
        if job.status in {models.JobStatus.failed, models.JobStatus.timed_out, models.JobStatus.cancelled}:
            if job.attempts >= job.max_attempts:
                items.append(_job_retry_item("retry_exhausted", job, now, repositories, applications, "Job has no retry attempts remaining"))
            else:
                items.append(_job_retry_item("retryable_failure", job, now, repositories, applications, "Job failed but still has retry attempts remaining"))
        if job.status == models.JobStatus.queued and _before(job.run_after, now) and _age_hours(job.run_after, now) >= 1:
            items.append(_job_retry_item("overdue_retry", job, now, repositories, applications, "Queued retry is past run_after"))
        if job.status == models.JobStatus.running and job.locked_at and _before(job.locked_at, now - timedelta(hours=1)):
            items.append(_job_retry_item("stale_running_lock", job, now, repositories, applications, "Running job lock is older than 1 hour"))
    return items


def job_backlog_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stmt = (
        select(models.Job)
        .where(
            models.Job.status.in_(
                [
                    models.JobStatus.queued,
                    models.JobStatus.running,
                    models.JobStatus.failed,
                    models.JobStatus.timed_out,
                    models.JobStatus.cancelled,
                ]
            )
        )
        .order_by(models.Job.created_at.asc(), models.Job.id.asc())
    )
    items = []
    for job in db.scalars(stmt):
        reason = _job_backlog_reason(job, now)
        if not reason:
            continue
        repository = db.get(models.Repository, job.repository_id) if job.repository_id else None
        application = db.get(models.Application, job.application_id) if job.application_id else None
        items.append(
            schemas.JobBacklogOut(
                id=job.id,
                job_type=job.job_type,
                status=job.status,
                repository_id=job.repository_id,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                application_id=job.application_id,
                application_name=application.name if application else None,
                attempts=job.attempts,
                max_attempts=job.max_attempts,
                run_after=job.run_after,
                locked_by=job.locked_by,
                age_hours=_age_hours(job.created_at, now),
                reason=reason,
                last_error=job.last_error,
                created_at=job.created_at,
            ).model_dump(mode="json")
        )
    return items


def job_concurrency_risk_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    jobs = list(
        db.scalars(
            select(models.Job)
            .where(
                models.Job.status.in_(
                    [
                        models.JobStatus.queued,
                        models.JobStatus.running,
                        models.JobStatus.failed,
                        models.JobStatus.timed_out,
                        models.JobStatus.cancelled,
                    ]
                )
            )
            .order_by(models.Job.created_at.asc(), models.Job.id.asc())
        )
    )
    active_by_key: dict[str, list[models.Job]] = {}
    for job in jobs:
        if job.status in {models.JobStatus.queued, models.JobStatus.running}:
            active_by_key.setdefault(_job_concurrency_key(job), []).append(job)
    duplicate_ids = {
        job.id: len(group)
        for group in active_by_key.values()
        if len(group) > 1
        for job in group
    }
    repositories = {repo.id: repo for repo in db.scalars(select(models.Repository))}
    applications = {app.id: app for app in db.scalars(select(models.Application))}
    items = []
    for job in jobs:
        duplicate_count = duplicate_ids.get(job.id, 0)
        if duplicate_count:
            items.append(_job_concurrency_item("duplicate_active_job", job, duplicate_count, now, repositories, applications, "Multiple queued/running jobs target the same work"))
        if job.status == models.JobStatus.running and job.locked_at and _before(job.locked_at, now - timedelta(hours=1)):
            items.append(_job_concurrency_item("stale_lock", job, duplicate_count, now, repositories, applications, "Running job lock is older than 1 hour"))
        if job.status in {models.JobStatus.failed, models.JobStatus.timed_out, models.JobStatus.cancelled} and job.attempts >= job.max_attempts:
            items.append(_job_concurrency_item("retry_exhausted", job, duplicate_count, now, repositories, applications, "Job exhausted retry attempts"))
    return items


def _job_backlog_reason(job: models.Job, now: datetime) -> str | None:
    if job.status == models.JobStatus.queued and _before(job.run_after, now):
        return "stale_queued" if _age_hours(job.created_at, now) >= 24 else "queued"
    if job.status == models.JobStatus.running and job.started_at and _age_hours(job.started_at, now) >= 24:
        return "stale_running"
    if job.status in {models.JobStatus.failed, models.JobStatus.timed_out, models.JobStatus.cancelled}:
        if job.attempts >= job.max_attempts:
            return "retry_exhausted"
        return job.status.value
    return None


def _age_hours(value, now: datetime) -> int:
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    return max(int((now - value).total_seconds() // 3600), 0)


def _job_concurrency_key(job: models.Job) -> str:
    payload = json.dumps(job.payload or {}, sort_keys=True, default=str)
    return "|".join(
        [
            job.job_type.value,
            str(job.repository_id or ""),
            str(job.application_id or ""),
            payload,
        ]
    )


def _job_concurrency_item(
    risk_type: str,
    job: models.Job,
    duplicate_count: int,
    now: datetime,
    repositories: dict,
    applications: dict,
    detail: str,
) -> dict:
    repository = repositories.get(job.repository_id) if job.repository_id else None
    application = applications.get(job.application_id) if job.application_id else None
    return schemas.JobConcurrencyRiskOut(
        risk_type=risk_type,
        job_id=job.id,
        job_type=job.job_type,
        status=job.status,
        repository_id=job.repository_id,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        application_id=job.application_id,
        application_name=application.name if application else None,
        duplicate_count=duplicate_count,
        locked_by=job.locked_by,
        locked_at=job.locked_at,
        attempts=job.attempts,
        max_attempts=job.max_attempts,
        detail=f"{detail}; age_hours={_age_hours(job.created_at, now)}",
        created_at=job.created_at,
    ).model_dump(mode="json")


def _job_retry_item(
    gap_type: str,
    job: models.Job,
    now: datetime,
    repositories: dict,
    applications: dict,
    detail: str,
) -> dict:
    repository = repositories.get(job.repository_id) if job.repository_id else None
    application = applications.get(job.application_id) if job.application_id else None
    return schemas.JobRetryPostureOut(
        gap_type=gap_type,
        job_id=job.id,
        job_type=job.job_type,
        status=job.status,
        repository_id=job.repository_id,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        application_id=job.application_id,
        application_name=application.name if application else None,
        attempts=job.attempts,
        max_attempts=job.max_attempts,
        run_after=job.run_after,
        locked_at=job.locked_at,
        age_hours=_age_hours(job.created_at, now),
        detail=detail,
        created_at=job.created_at,
    ).model_dump(mode="json")


def _before(value, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
