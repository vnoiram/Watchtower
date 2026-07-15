from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.auto_merge import list_auto_merge_eligibility
from api.app.routers.sbom_coverage import list_sbom_coverage
from api.app.routers.sla import count_sla_breached_findings

router = APIRouter(prefix="/kpis", tags=["kpis"])


@router.get("/summary", response_model=list[schemas.KpiMetricOut])
def kpi_summary(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    applications = list(db.scalars(select(models.Application)))
    scans = list(db.scalars(select(models.Scan)))
    findings = list(db.scalars(select(models.Finding)))
    notifications = list(db.scalars(select(models.Notification)))
    ai_fix_actions = list(
        db.scalars(select(models.RemediationAction).where(models.RemediationAction.action_type == "ai_fix"))
    )
    sbom_coverage = list_sbom_coverage(limit=100, db=db, _=None).items
    covered_apps = sum(1 for item in sbom_coverage if item["has_active_source_sbom"])
    daily_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    apps_scanned_daily = {
        scan.application_id for scan in scans if _after_cutoff(scan.created_at, daily_cutoff)
    }
    failed_scans = [
        scan for scan in scans if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out}
    ]
    sent_notifications = [notification for notification in notifications if notification.status == "sent"]
    failed_notifications = [
        notification for notification in notifications if notification.status == "failed"
    ]
    successful_ai_fix = [
        action
        for action in ai_fix_actions
        if action.status in {"succeeded", "merged", "closed"}
        or (action.metadata_json or {}).get("validation_status") == "succeeded"
    ]
    auto_merge_items = list_auto_merge_eligibility(limit=100, db=db, _=None).items
    auto_merge_eligible = sum(1 for item in auto_merge_items if item["allowed"])

    return [
        _metric(
            "sbom_coverage_percent",
            _percent(covered_apps, len(applications)),
            "percent",
            "Applications with an active source SBOM",
        ),
        _metric(
            "daily_scan_coverage_percent",
            _percent(len(apps_scanned_daily), len(applications)),
            "percent",
            "Applications scanned in the last 24 hours",
        ),
        _metric(
            "scan_failure_rate_percent",
            _percent(len(failed_scans), len(scans)),
            "percent",
            "Failed or timed out scans among all scan records",
        ),
        _metric(
            "open_finding_count",
            sum(1 for finding in findings if finding.status == models.FindingStatus.open),
            "count",
            "Open findings",
        ),
        _metric(
            "resolved_finding_count",
            sum(1 for finding in findings if finding.status == models.FindingStatus.resolved),
            "count",
            "Resolved findings",
        ),
        _metric(
            "notification_success_rate_percent",
            _percent(len(sent_notifications), len(sent_notifications) + len(failed_notifications)),
            "percent",
            "Sent notifications among terminal sent/failed notifications",
        ),
        _metric(
            "ai_fix_success_rate_percent",
            _percent(len(successful_ai_fix), len(ai_fix_actions)),
            "percent",
            "AI fix actions with succeeded validation or terminal success status",
        ),
        _metric(
            "auto_merge_eligible_count",
            auto_merge_eligible,
            "count",
            "Remediation actions currently eligible by dry-run auto merge policy",
        ),
        _metric(
            "sla_breach_count",
            count_sla_breached_findings(db),
            "count",
            "Open findings past the severity SLA",
        ),
    ]


def scan_failure_rate_percent(db: Session) -> float:
    scans = list(db.scalars(select(models.Scan)))
    failed = sum(1 for scan in scans if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out})
    return _percent(failed, len(scans))


def notification_failure_count(db: Session) -> int:
    return (
        db.scalar(
            select(func.count()).select_from(models.Notification).where(models.Notification.status == "failed")
        )
        or 0
    )


def _metric(metric: str, value: float, unit: str, detail: str) -> schemas.KpiMetricOut:
    return schemas.KpiMetricOut(metric=metric, value=value, unit=unit, detail=detail)


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def _after_cutoff(value: datetime, cutoff: datetime) -> bool:
    if value.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=None)
    return value >= cutoff
