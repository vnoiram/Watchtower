from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.auto_merge import list_auto_merge_eligibility
from api.app.routers.quality import reopen_risk_count
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


@router.get("/efficiency", response_model=list[schemas.KpiMetricOut])
def efficiency_kpis(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    findings = list(db.scalars(select(models.Finding)))
    notifications = list(db.scalars(select(models.Notification).where(models.Notification.status == "sent")))
    actions = list(db.scalars(select(models.RemediationAction)))
    issue_actions = [
        action for action in actions if action.action_type == "github_issue" and action.status in {"created", "closed"}
    ]
    auto_resolved = [
        finding
        for finding in findings
        if finding.status == models.FindingStatus.resolved
        and finding.resolved_at is not None
        and _has_successful_action_after(actions, finding)
    ]
    return [
        _metric(
            "mean_time_to_detect_hours",
            _mean_hours([_scan_to_finding_hours(db, finding) for finding in findings]),
            "hours",
            "Average time from first scan to finding creation",
        ),
        _metric(
            "mean_time_to_notify_hours",
            _mean_hours([_finding_to_notification_hours(db, notification) for notification in notifications]),
            "hours",
            "Average time from finding creation to sent notification",
        ),
        _metric(
            "mean_time_to_remediate_hours",
            _mean_hours([_finding_to_resolution_hours(finding) for finding in findings]),
            "hours",
            "Average time from finding creation to resolution",
        ),
        _metric(
            "issue_creation_rate_percent",
            _percent(len({action.finding_id for action in issue_actions}), len(findings)),
            "percent",
            "Findings with a created or closed GitHub issue action",
        ),
        _metric(
            "auto_resolution_rate_percent",
            _percent(len(auto_resolved), len([finding for finding in findings if finding.status == models.FindingStatus.resolved])),
            "percent",
            "Resolved findings with successful remediation evidence",
        ),
    ]


@router.get("/quality", response_model=list[schemas.KpiMetricOut])
def quality_kpis(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    findings = list(db.scalars(select(models.Finding)))
    vex_statements = list(db.scalars(select(models.VexStatement)))
    actions = list(db.scalars(select(models.RemediationAction)))
    ai_fix_actions = [action for action in actions if action.action_type == "ai_fix"]
    false_positive = [
        finding for finding in findings if finding.status == models.FindingStatus.false_positive
    ]
    expired_vex = [
        vex
        for vex in vex_statements
        if _before(vex.review_date, datetime.now(timezone.utc))
    ]
    failed_auto_merge = [
        action
        for action in ai_fix_actions
        if action.status in {"failed", "blocked"}
        or (action.metadata_json or {}).get("auto_merge_allowed") is False
    ]
    ci_observed = [action for action in actions if "ci_passed" in (action.metadata_json or {})]
    ci_failed = [action for action in ci_observed if (action.metadata_json or {}).get("ci_passed") is False]
    reopen_count = reopen_risk_count(db)
    return [
        _metric(
            "false_positive_rate_percent",
            _percent(len(false_positive), len(findings)),
            "percent",
            "Findings classified as false positives among all findings",
        ),
        _metric(
            "expired_vex_rate_percent",
            _percent(len(expired_vex), len(vex_statements)),
            "percent",
            "Expired VEX statements among all VEX statements",
        ),
        _metric(
            "auto_merge_failure_rate_percent",
            _percent(len(failed_auto_merge), len(ai_fix_actions)),
            "percent",
            "AI fix actions blocked or failed for auto-merge",
        ),
        _metric(
            "pr_ci_failure_rate_percent",
            _percent(len(ci_failed), len(ci_observed)),
            "percent",
            "Remediation actions with failed CI among actions with CI metadata",
        ),
        _metric(
            "reopen_risk_count",
            reopen_count,
            "count",
            "Resolved findings seen again after resolution",
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


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _mean_hours(values: list[float | None]) -> float:
    present = [value for value in values if value is not None]
    return round(sum(present) / len(present), 1) if present else 0.0


def _scan_to_finding_hours(db: Session, finding: models.Finding) -> float | None:
    if not finding.first_seen_scan_id:
        return None
    scan = db.get(models.Scan, finding.first_seen_scan_id)
    if not scan:
        return None
    return _hours_between(scan.created_at, finding.created_at)


def _finding_to_notification_hours(db: Session, notification: models.Notification) -> float | None:
    finding_id = (notification.metadata_json or {}).get("finding_id")
    if not finding_id:
        return None
    try:
        finding_uuid = UUID(str(finding_id))
    except ValueError:
        return None
    finding = db.get(models.Finding, finding_uuid)
    if not finding or not notification.sent_at:
        return None
    return _hours_between(finding.created_at, notification.sent_at)


def _finding_to_resolution_hours(finding: models.Finding) -> float | None:
    if finding.status != models.FindingStatus.resolved or not finding.resolved_at:
        return None
    return _hours_between(finding.created_at, finding.resolved_at)


def _has_successful_action_after(actions: list[models.RemediationAction], finding: models.Finding) -> bool:
    for action in actions:
        metadata = action.metadata_json or {}
        if action.finding_id != finding.id:
            continue
        if action.status in {"succeeded", "merged", "closed"} or metadata.get("validation_status") == "succeeded":
            return True
    return False


def _hours_between(start: datetime, end: datetime) -> float:
    if start.tzinfo is None and end.tzinfo is not None:
        end = end.replace(tzinfo=None)
    if start.tzinfo is not None and end.tzinfo is None:
        start = start.replace(tzinfo=None)
    return max(round((end - start).total_seconds() / 3600, 1), 0.0)
