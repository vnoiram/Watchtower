from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.job_health import job_health_reason
from api.app.routers.scan_health import list_scan_health
from api.app.routers.sla import count_sla_breached_findings

router = APIRouter(prefix="/operations", tags=["operations"])


@router.get("/readiness", response_model=list[schemas.OperationsReadinessOut])
def operations_readiness(
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    notification_configured = bool(
        settings.slack_webhook_url
        or settings.discord_webhook_url
        or (settings.smtp_host and settings.smtp_from)
    )
    return [
        _readiness("github_token", bool(settings.github_token), "GitHub token is configured"),
        _readiness(
            "github_app",
            bool(settings.github_app_id and settings.github_private_key),
            "GitHub App id and private key are configured",
        ),
        _readiness(
            "github_webhook_secret",
            bool(settings.github_webhook_secret),
            "GitHub webhook signature validation can be enabled",
        ),
        _readiness("notifications", notification_configured, "At least one notification channel is configured"),
        _readiness(
            "object_storage",
            bool(
                settings.minio_endpoint
                and settings.minio_access_key
                and settings.minio_secret_key
                and settings.minio_bucket
            ),
            f"Object storage bucket setting: {settings.minio_bucket}",
        ),
        _readiness(
            "scan_scheduler",
            settings.scan_scheduler_interval_seconds > 0 and settings.scan_scheduler_stale_after_hours > 0,
            (
                f"interval={settings.scan_scheduler_interval_seconds}s "
                f"stale_after={settings.scan_scheduler_stale_after_hours}h"
            ),
        ),
        _readiness(
            "api_default_role",
            settings.api_default_role in {"viewer", "operator", "admin"},
            f"default_role={settings.api_default_role}",
        ),
    ]


@router.get("/daily", response_model=list[schemas.DailyOperationCheckOut])
def daily_operations(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent_sync_jobs = _recent_jobs(db, models.JobType.repository_sync, cutoff)
    recent_scan_jobs = _recent_jobs(db, models.JobType.scan, cutoff)
    unhealthy_jobs = [
        job for job in db.execute(select(models.Job)).scalars() if job_health_reason(job, now)
    ]
    failed_notifications = list(
        db.scalars(select(models.Notification).where(models.Notification.status == "failed"))
    )
    expired_vex = list(
        db.scalars(select(models.VexStatement).where(models.VexStatement.review_date < now))
    )
    sla_breaches = count_sla_breached_findings(db, now)
    stale_scans = len(list_scan_health(db=db, _=None).items)

    return [
        _daily_check(
            "repository_sync_24h",
            "ok" if recent_sync_jobs else "warn",
            len(recent_sync_jobs),
            "Repository sync jobs completed or queued in the last 24 hours",
        ),
        _daily_check(
            "scan_jobs_24h",
            "ok" if recent_scan_jobs else "warn",
            len(recent_scan_jobs),
            "Scan jobs completed or queued in the last 24 hours",
        ),
        _daily_check(
            "unhealthy_jobs",
            "ok" if not unhealthy_jobs else "fail",
            len(unhealthy_jobs),
            "Failed, timed out, stale running, or overdue queued jobs",
        ),
        _daily_check(
            "failed_notifications",
            "ok" if not failed_notifications else "fail",
            len(failed_notifications),
            "Notifications with failed delivery status",
        ),
        _daily_check(
            "expired_vex",
            "ok" if not expired_vex else "warn",
            len(expired_vex),
            "VEX statements past review date",
        ),
        _daily_check(
            "sla_breaches",
            "ok" if not sla_breaches else "fail",
            sla_breaches,
            "Open findings past the severity SLA",
        ),
        _daily_check(
            "scan_health_issues",
            "ok" if not stale_scans else "warn",
            stale_scans,
            "Failed, partial, or stale application scans",
        ),
    ]


def _readiness(check: str, configured: bool, detail: str) -> schemas.OperationsReadinessOut:
    return schemas.OperationsReadinessOut(
        check=check,
        status="ok" if configured else "warn",
        configured=configured,
        detail=detail,
    )


def _daily_check(check: str, status: str, count: int, detail: str) -> schemas.DailyOperationCheckOut:
    return schemas.DailyOperationCheckOut(check=check, status=status, count=count, detail=detail)


def _recent_jobs(db: Session, job_type: models.JobType, cutoff: datetime) -> list[models.Job]:
    jobs = db.scalars(select(models.Job).where(models.Job.job_type == job_type))
    return [
        job
        for job in jobs
        if _after_cutoff(job.created_at, cutoff)
        or (job.completed_at is not None and _after_cutoff(job.completed_at, cutoff))
    ]


def _after_cutoff(value: datetime, cutoff: datetime) -> bool:
    if value.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=None)
    return value >= cutoff
