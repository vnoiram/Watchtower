from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Job, JobStatus, JobType


def enqueue_job(
    db: Session,
    job_type: JobType,
    repository_id: UUID | None = None,
    application_id: UUID | None = None,
    payload: dict | None = None,
    max_attempts: int = 3,
) -> Job:
    job = Job(
        job_type=job_type,
        repository_id=repository_id,
        application_id=application_id,
        payload=payload or {},
        max_attempts=max_attempts,
    )
    db.add(job)
    db.flush()
    return job


def lock_next_job(db: Session, worker_id: str) -> Job | None:
    now = datetime.now(timezone.utc)
    stmt = (
        select(Job)
        .where(Job.status == JobStatus.queued, Job.run_after <= now)
        .order_by(Job.created_at.asc())
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    job = db.execute(stmt).scalar_one_or_none()
    if not job:
        return None
    job.status = JobStatus.running
    job.locked_by = worker_id
    job.locked_at = now
    job.started_at = now
    job.attempts += 1
    db.flush()
    return job


def mark_job_succeeded(job: Job) -> None:
    job.status = JobStatus.succeeded
    job.completed_at = datetime.now(timezone.utc)
    job.last_error = None


def mark_job_failed(job: Job, error: str) -> None:
    job.last_error = error
    if job.attempts >= job.max_attempts:
        job.status = JobStatus.failed
        job.completed_at = datetime.now(timezone.utc)
    else:
        job.status = JobStatus.queued
        job.locked_by = None
        job.locked_at = None

