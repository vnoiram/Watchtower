from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

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
    return schemas.DashboardSummary(
        repositories=repositories,
        applications=applications,
        open_critical=open_critical,
        open_high=open_high,
        stale_scans=stale_scans,
        failed_jobs=failed_jobs,
        expired_vex=expired_vex,
    )

