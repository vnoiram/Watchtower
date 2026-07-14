from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import Application, Job, JobStatus, JobType, Repository, Scan, now_utc
from api.app.services.jobs import enqueue_job


@dataclass
class StaleRepositoryScanEnqueueResult:
    jobs: list[Job] = field(default_factory=list)
    considered_count: int = 0
    archived_count: int = 0
    missing_source_count: int = 0
    fresh_count: int = 0
    already_queued_count: int = 0

    @property
    def enqueued_count(self) -> int:
        return len(self.jobs)


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _latest_repository_scan_created_at(db: Session, repository: Repository) -> datetime | None:
    return db.scalar(
        select(Scan.created_at)
        .join(Application, Scan.application_id == Application.id)
        .where(Application.repository_id == repository.id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


def _has_active_scan_job(db: Session, repository: Repository) -> bool:
    jobs = db.scalars(
        select(Job).where(
            Job.job_type == JobType.scan,
            Job.status.in_([JobStatus.queued, JobStatus.running]),
        )
    )
    repository_id = str(repository.id)
    return any(
        job.repository_id == repository.id
        or str((job.payload or {}).get("repository_id")) == repository_id
        for job in jobs
    )


def enqueue_stale_repository_scans(
    db: Session,
    *,
    stale_after_hours: int = 24,
    limit: int | None = None,
) -> StaleRepositoryScanEnqueueResult:
    cutoff = now_utc() - timedelta(hours=stale_after_hours)
    result = StaleRepositoryScanEnqueueResult()
    stmt = select(Repository).order_by(Repository.created_at.asc(), Repository.id.asc())
    repositories = db.scalars(stmt)

    for repository in repositories:
        result.considered_count += 1
        if repository.archived:
            result.archived_count += 1
            continue
        if not (repository.url or repository.local_path):
            result.missing_source_count += 1
            continue

        latest_scan_created_at = _latest_repository_scan_created_at(db, repository)
        if latest_scan_created_at and _as_aware_utc(latest_scan_created_at) >= cutoff:
            result.fresh_count += 1
            continue

        if _has_active_scan_job(db, repository):
            result.already_queued_count += 1
            continue

        job = enqueue_job(
            db,
            JobType.scan,
            repository_id=repository.id,
            payload={"repository_id": str(repository.id), "trigger_type": "schedule"},
        )
        result.jobs.append(job)
        if limit is not None and len(result.jobs) >= limit:
            break

    return result
