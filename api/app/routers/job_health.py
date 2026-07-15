from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/job-health", tags=["job-health"])
STALE_JOB_AGE = timedelta(hours=1)


@router.get("", response_model=schemas.CursorPage)
def list_job_health(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    stmt = select(models.Job).order_by(models.Job.created_at.desc(), models.Job.id.asc())

    items = []
    for job in db.execute(stmt).scalars():
        reason = job_health_reason(job, now)
        if not reason:
            continue
        repository = db.get(models.Repository, job.repository_id) if job.repository_id else None
        application = db.get(models.Application, job.application_id) if job.application_id else None
        items.append(
            schemas.JobHealthOut(
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
                started_at=job.started_at,
                completed_at=job.completed_at,
                last_error=job.last_error,
                created_at=job.created_at,
                health_reason=reason,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


def job_health_reason(job: models.Job, now: datetime) -> str | None:
    if job.status in {
        models.JobStatus.failed,
        models.JobStatus.timed_out,
        models.JobStatus.cancelled,
    }:
        return job.status.value
    if job.status == models.JobStatus.running and job.started_at:
        if job.started_at < _matching_datetime(now - STALE_JOB_AGE, job.started_at):
            return "stale_running"
    if job.status == models.JobStatus.queued:
        if job.run_after < _matching_datetime(now - STALE_JOB_AGE, job.run_after):
            return "overdue_queued"
    return None


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
