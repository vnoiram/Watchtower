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


@router.get("/operational-load", response_model=list[schemas.KpiMetricOut])
def operational_load_kpis(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    audit_logs = [log for log in db.scalars(select(models.AuditLog)) if _after_cutoff(log.created_at, cutoff)]
    actions = list(db.scalars(select(models.RemediationAction)))
    manual_checks = sum(1 for log in audit_logs if _manual_action_reason(log))
    manual_issues = sum(1 for log in audit_logs if log.action in {"finding.github_issue.enqueue", "github.issue.create"})
    manual_dependency_updates = sum(1 for log in audit_logs if _manual_action_reason(log) == "manual_dependency_update")
    open_findings = sum(1 for finding in db.scalars(select(models.Finding)) if finding.status == models.FindingStatus.open)
    stale_prs = sum(1 for action in actions if _has_pr_signal(action) and _before(action.updated_at, cutoff))
    return [
        _metric("monthly_manual_check_count", manual_checks, "count", "Manual review or operation audit logs in the last 30 days"),
        _metric("manual_issue_creation_count", manual_issues, "count", "Manual issue creation audit logs in the last 30 days"),
        _metric("manual_dependency_update_count", manual_dependency_updates, "count", "Manual dependency update audit logs in the last 30 days"),
        _metric("unaddressed_finding_count", open_findings, "count", "Open findings awaiting remediation"),
        _metric("long_stale_pr_count", stale_prs, "count", "PR-like remediation actions untouched for 30 days"),
    ]


@router.get("/evidence", response_model=schemas.CursorPage)
def list_kpi_evidence(
    limit: int = 50,
    metric: str | None = None,
    included: bool | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = kpi_evidence_items(db)
    if metric:
        items = [item for item in items if item["metric"] == metric]
    if included is not None:
        items = [item for item in items if item["included"] is included]
    if status:
        items = [item for item in items if item["status"] == status]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/timeline", response_model=schemas.CursorPage)
def list_efficiency_timeline(
    limit: int = 50,
    metric: str | None = None,
    severity: models.Severity | None = None,
    breached: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = efficiency_timeline_items(db)
    if metric:
        items = [item for item in items if item["metric"] == metric]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if breached is not None:
        items = [item for item in items if item["breached"] is breached]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


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


def kpi_evidence_items(db: Session) -> list[dict]:
    items = []
    daily_cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    active_sbom_app_ids = set(
        db.scalars(
            select(models.Sbom.application_id).where(
                models.Sbom.active.is_(True),
                models.Sbom.sbom_kind == "source",
            )
        )
    )
    latest_scan_by_app = _latest_scan_by_application(list(db.scalars(select(models.Scan))))
    for application, repository in db.execute(
        select(models.Application, models.Repository)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
    ):
        has_sbom = application.id in active_sbom_app_ids
        items.append(_kpi_evidence("sbom_coverage", "application", str(application.id), has_sbom, "covered" if has_sbom else "missing", application, repository, "Application active source SBOM coverage"))
        latest_scan = latest_scan_by_app.get(application.id)
        daily = latest_scan is not None and _after_cutoff(latest_scan.created_at, daily_cutoff)
        items.append(_kpi_evidence("daily_scan_coverage", "application", str(application.id), daily, "covered" if daily else "missing", application, repository, "Application scanned in the last 24 hours"))

    for notification in db.scalars(select(models.Notification).order_by(models.Notification.created_at.desc(), models.Notification.id.asc())):
        finding, application, repository = _notification_context(db, notification)
        included = notification.status == "sent"
        if notification.status in {"sent", "failed"}:
            items.append(_kpi_evidence("notification_success", "notification", str(notification.id), included, notification.status, application, repository, "Terminal notification delivery record"))

    for action, finding, application, repository in _action_context_rows(db):
        metadata = action.metadata_json or {}
        ai_success = action.action_type == "ai_fix" and (
            action.status in {"succeeded", "merged", "closed"} or metadata.get("validation_status") == "succeeded"
        )
        if action.action_type == "ai_fix":
            items.append(_kpi_evidence("ai_fix_success", "remediation_action", str(action.id), ai_success, action.status, application, repository, "AI fix action success evidence"))
        if "ci_passed" in metadata:
            ci_success = metadata.get("ci_passed") is True
            items.append(_kpi_evidence("pr_ci_success", "remediation_action", str(action.id), ci_success, "passed" if ci_success else "failed", application, repository, "PR CI result evidence"))
        if finding.fixed_version and finding.severity in {models.Severity.critical, models.Severity.high}:
            created = action.action_type in {"github_issue", "ai_fix"} or bool(action.url or action.branch)
            items.append(_kpi_evidence("auto_pr_creation", "remediation_action", str(action.id), created, action.status, application, repository, "Fixable critical/high finding remediation action evidence"))
    return items


def efficiency_timeline_items(db: Session) -> list[dict]:
    items = []
    notifications_by_finding = _sent_notifications_by_finding(db)
    actions_by_finding = _first_actions_by_finding(db)
    rows = db.execute(
        select(models.Finding, models.Application, models.Repository)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Finding.created_at.desc(), models.Finding.id.asc())
    )
    for finding, application, repository in rows:
        first_scan = db.get(models.Scan, finding.first_seen_scan_id) if finding.first_seen_scan_id else None
        notification = notifications_by_finding.get(finding.id)
        action = actions_by_finding.get(finding.id)
        for metric, start_at, end_at, threshold in [
            ("mttd", first_scan.created_at if first_scan else None, finding.created_at, 24),
            ("mttn", finding.created_at, notification.sent_at if notification else None, 4 if finding.severity == models.Severity.critical else 24),
            ("mttr", finding.created_at, finding.resolved_at, 168 if finding.severity in {models.Severity.critical, models.Severity.high} else 720),
        ]:
            duration = _hours_between(start_at, end_at) if start_at and end_at else None
            breached = duration is None or duration > threshold
            items.append(
                schemas.EfficiencyTimelineOut(
                    finding_id=finding.id,
                    metric=metric,
                    severity=finding.severity,
                    application_id=application.id,
                    application_name=application.name,
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                    first_scan_at=first_scan.created_at if first_scan else None,
                    finding_created_at=finding.created_at,
                    notification_sent_at=notification.sent_at if notification else None,
                    first_action_at=action.created_at if action else None,
                    resolved_at=finding.resolved_at,
                    duration_hours=duration,
                    breached=breached,
                    detail="Timeline evidence is within threshold" if not breached else "Timeline evidence is missing or past threshold",
                ).model_dump(mode="json")
            )
    return items


def _metric(metric: str, value: float, unit: str, detail: str) -> schemas.KpiMetricOut:
    return schemas.KpiMetricOut(metric=metric, value=value, unit=unit, detail=detail)


def _kpi_evidence(
    metric: str,
    record_type: str,
    record_id: str,
    included: bool,
    status: str,
    application: models.Application | None,
    repository: models.Repository | None,
    detail: str,
) -> dict:
    return schemas.KpiEvidenceOut(
        metric=metric,
        record_type=record_type,
        record_id=record_id,
        included=included,
        status=status,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        detail=detail,
    ).model_dump(mode="json")


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


def _latest_scan_by_application(scans: list[models.Scan]) -> dict:
    latest = {}
    for scan in sorted(scans, key=lambda item: (_sort_datetime(item.created_at), item.id), reverse=True):
        latest.setdefault(scan.application_id, scan)
    return latest


def _sort_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


def _notification_context(
    db: Session,
    notification: models.Notification,
) -> tuple[models.Finding | None, models.Application | None, models.Repository | None]:
    finding_id = (notification.metadata_json or {}).get("finding_id")
    if not finding_id:
        return None, None, None
    try:
        finding = db.get(models.Finding, UUID(str(finding_id)))
    except ValueError:
        return None, None, None
    application = db.get(models.Application, finding.application_id) if finding else None
    repository = db.get(models.Repository, application.repository_id) if application else None
    return finding, application, repository


def _action_context_rows(db: Session):
    return db.execute(
        select(models.RemediationAction, models.Finding, models.Application, models.Repository)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())
    )


def _sent_notifications_by_finding(db: Session) -> dict[UUID, models.Notification]:
    notifications = {}
    for notification in db.scalars(
        select(models.Notification).where(models.Notification.status == "sent").order_by(models.Notification.sent_at.asc())
    ):
        finding, _, _ = _notification_context(db, notification)
        if finding:
            notifications.setdefault(finding.id, notification)
    return notifications


def _first_actions_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    actions = {}
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.created_at.asc(), models.RemediationAction.id.asc())):
        actions.setdefault(action.finding_id, action)
    return actions


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


def _manual_action_reason(audit_log: models.AuditLog) -> str | None:
    metadata = audit_log.metadata_json or {}
    searchable = f"{audit_log.action} {metadata}".lower()
    if audit_log.action in {"scan.create", "job.create", "repository.scan.enqueue", "finding.github_issue.enqueue"}:
        return "manual_operation"
    if "dependency" in searchable:
        return "manual_dependency_update"
    if "manual" in searchable:
        return "manual"
    return None


def _has_pr_signal(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    return bool(
        action.branch
        or action.url
        or action.provider_id
        or metadata.get("pull_request_url")
        or metadata.get("pr_number")
    )


def _hours_between(start: datetime, end: datetime) -> float:
    if start.tzinfo is None and end.tzinfo is not None:
        end = end.replace(tzinfo=None)
    if start.tzinfo is not None and end.tzinfo is None:
        start = start.replace(tzinfo=None)
    return max(round((end - start).total_seconds() / 3600, 1), 0.0)
