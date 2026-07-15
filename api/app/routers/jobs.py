from datetime import datetime, timezone

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


def _before(value, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
