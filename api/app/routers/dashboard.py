from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.isolated_lane import count_isolated_applications
from api.app.routers.job_health import job_health_reason
from api.app.routers.kpis import notification_failure_count, scan_failure_rate_percent
from api.app.routers.operations import manual_workload_count
from api.app.routers.scheduled_scan_coverage import missing_scheduled_scan_count
from api.app.routers.sla import count_sla_breached_findings

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    repositories = db.scalar(select(func.count()).select_from(models.Repository)) or 0
    applications = db.scalar(select(func.count()).select_from(models.Application)) or 0
    open_critical = db.scalar(select(func.count()).select_from(models.Finding).where(models.Finding.status == models.FindingStatus.open, models.Finding.severity == models.Severity.critical)) or 0
    open_high = db.scalar(select(func.count()).select_from(models.Finding).where(models.Finding.status == models.FindingStatus.open, models.Finding.severity == models.Severity.high)) or 0
    failed_jobs = db.scalar(select(func.count()).select_from(models.Job).where(models.Job.status == models.JobStatus.failed)) or 0
    expired_vex = db.scalar(select(func.count()).select_from(models.VexStatement).where(models.VexStatement.review_date < datetime.now(timezone.utc))) or 0
    stale_scans = db.scalar(select(func.count()).select_from(models.Application).where(~models.Application.scans.any(models.Scan.created_at >= cutoff))) or 0
    missing_active_sbom = (
        db.scalar(
            select(func.count()).select_from(models.Application).where(
                ~models.Application.id.in_(
                    select(models.Sbom.application_id).where(
                        models.Sbom.active.is_(True),
                        models.Sbom.sbom_kind == "source",
                    )
                )
            )
        )
        or 0
    )
    sbom_coverage_percent = (
        round(((applications - missing_active_sbom) / applications) * 100, 1) if applications else 0.0
    )
    now = datetime.now(timezone.utc)
    unhealthy_jobs = sum(1 for job in db.execute(select(models.Job)).scalars() if job_health_reason(job, now))
    sla_breached_findings = count_sla_breached_findings(db, now)
    isolated_applications = count_isolated_applications(db)
    scan_failure_rate = scan_failure_rate_percent(db)
    notification_failures = notification_failure_count(db)
    manual_workload_items = manual_workload_count(db)
    missing_scheduled_scans = missing_scheduled_scan_count(db)
    return schemas.DashboardSummary(
        repositories=repositories,
        applications=applications,
        open_critical=open_critical,
        open_high=open_high,
        stale_scans=stale_scans,
        failed_jobs=failed_jobs,
        expired_vex=expired_vex,
        sbom_coverage_percent=sbom_coverage_percent,
        missing_active_sbom=missing_active_sbom,
        unhealthy_jobs=unhealthy_jobs,
        sla_breached_findings=sla_breached_findings,
        isolated_applications=isolated_applications,
        scan_failure_rate_percent=scan_failure_rate,
        notification_failure_count=notification_failures,
        manual_workload_items=manual_workload_items,
        missing_scheduled_scans=missing_scheduled_scans,
    )
