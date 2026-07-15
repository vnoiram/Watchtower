from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.auto_merge import automation_guardrail_count
from api.app.routers.governance import exposure_review_count, quarterly_review_count
from api.app.routers.integrations import github_integration_issue_count
from api.app.routers.isolated_lane import (
    count_isolated_applications,
    isolated_safeguard_count,
    isolated_scan_health_count,
)
from api.app.routers.job_health import job_health_reason
from api.app.routers.kpis import notification_failure_count, scan_failure_rate_percent
from api.app.routers.notifications import notification_slo_breach_count
from api.app.routers.operations import (
    control_evidence_count,
    failure_signal_count,
    manual_action_count,
    manual_workload_count,
    monthly_review_count,
    phase_readiness_count,
    queue_pressure_count,
    rollback_readiness_count,
)
from api.app.routers.quality import reopen_risk_count
from api.app.routers.remediation import (
    fixable_gap_count,
    pr_ci_failure_count,
    remediation_coverage_count,
    stale_remediation_count,
)
from api.app.routers.rollout import application_readiness_count, rollout_gap_count, rollout_wave_gap_count
from api.app.routers.scheduled_scan_coverage import missing_scheduled_scan_count
from api.app.routers.security import rbac_review_count
from api.app.routers.sla import count_sla_breached_findings
from api.app.routers.storage import retention_review_count, storage_pressure_count

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=schemas.DashboardSummary)
def dashboard_summary(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    if not isinstance(settings, Settings):
        settings = get_settings()
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
    notification_slo_breaches = notification_slo_breach_count(db)
    stale_remediation_items = stale_remediation_count(db)
    manual_actions = manual_action_count(db)
    exposure_items = exposure_review_count(db)
    retention_items = retention_review_count(db)
    reopen_risk_items = reopen_risk_count(db)
    rbac_review_items = rbac_review_count(db, settings)
    rollout_gap_items = rollout_gap_count(db)
    rollout_wave_gap_items = rollout_wave_gap_count(db)
    github_integration_issues = github_integration_issue_count(db, settings)
    failure_signal_items = failure_signal_count(db)
    isolated_safeguard_items = isolated_safeguard_count(db)
    quarterly_review_items = quarterly_review_count(db)
    application_readiness_items = application_readiness_count(db)
    remediation_coverage_items = remediation_coverage_count(db)
    monthly_review_items = monthly_review_count(db)
    phase_readiness_items = phase_readiness_count(db)
    control_evidence_items = control_evidence_count(db)
    automation_guardrail_items = automation_guardrail_count(db)
    rollback_readiness_items = rollback_readiness_count(db)
    queue_pressure_items = queue_pressure_count(db)
    storage_pressure_items = storage_pressure_count(db)
    fixable_gap_items = fixable_gap_count(db)
    pr_ci_failure_items = pr_ci_failure_count(db)
    isolated_scan_health_items = isolated_scan_health_count(db)
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
        notification_slo_breaches=notification_slo_breaches,
        stale_remediation_items=stale_remediation_items,
        manual_action_count=manual_actions,
        exposure_review_items=exposure_items,
        retention_review_items=retention_items,
        reopen_risk_items=reopen_risk_items,
        rbac_review_items=rbac_review_items,
        rollout_gap_items=rollout_gap_items,
        rollout_wave_gap_items=rollout_wave_gap_items,
        github_integration_issues=github_integration_issues,
        failure_signal_items=failure_signal_items,
        isolated_safeguard_items=isolated_safeguard_items,
        quarterly_review_items=quarterly_review_items,
        application_readiness_items=application_readiness_items,
        remediation_coverage_items=remediation_coverage_items,
        monthly_review_items=monthly_review_items,
        phase_readiness_items=phase_readiness_items,
        control_evidence_items=control_evidence_items,
        automation_guardrail_items=automation_guardrail_items,
        rollback_readiness_items=rollback_readiness_items,
        queue_pressure_items=queue_pressure_items,
        storage_pressure_items=storage_pressure_items,
        fixable_gap_items=fixable_gap_items,
        pr_ci_failure_items=pr_ci_failure_items,
        isolated_scan_health_items=isolated_scan_health_items,
    )
