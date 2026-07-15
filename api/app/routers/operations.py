from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.job_health import job_health_reason
from api.app.routers.remediation import stale_remediation_count
from api.app.routers.scan_health import list_scan_health
from api.app.routers.sla import count_sla_breached_findings
from api.app.routers.storage import list_storage_cleanup_candidates
from api.app.services.remediation import ACTION_TYPE_AI_FIX

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


@router.get("/workload", response_model=list[schemas.OperationalWorkloadOut])
def operational_workload(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return _workload_rows(db)


@router.get("/backup-readiness", response_model=list[schemas.BackupReadinessOut])
def backup_readiness(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    storage_configured = bool(
        settings.minio_endpoint
        and settings.minio_access_key
        and settings.minio_secret_key
        and settings.minio_bucket
    )
    missing_storage_keys = _count(
        db,
        select(models.Sbom).where(
            (models.Sbom.storage_key.is_(None)) | (models.Sbom.storage_key == ""),
        ),
    )
    source_sbom_artifacts = _source_sbom_artifact_count(db)
    source_sboms = _count(db, select(models.Sbom).where(models.Sbom.sbom_kind == "source"))
    cleanup_backlog = len(list_storage_cleanup_candidates(db=db, _=None).items)
    return [
        _backup_check(
            "object_storage",
            "ok" if storage_configured else "fail",
            1 if storage_configured else 0,
            f"Object storage bucket setting: {settings.minio_bucket}",
        ),
        _backup_check(
            "sbom_storage_keys",
            "ok" if not missing_storage_keys else "fail",
            missing_storage_keys,
            "SBOM records without a storage key",
        ),
        _backup_check(
            "source_sbom_artifacts",
            "ok" if source_sbom_artifacts >= source_sboms else "warn",
            source_sbom_artifacts,
            f"Source SBOM artifacts recorded for {source_sboms} source SBOMs",
        ),
        _backup_check(
            "cleanup_backlog",
            "ok" if not cleanup_backlog else "warn",
            cleanup_backlog,
            "Storage cleanup candidates awaiting review",
        ),
    ]


@router.get("/restore-readiness", response_model=list[schemas.RestoreReadinessOut])
def restore_readiness(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    storage_configured = bool(
        settings.minio_endpoint
        and settings.minio_access_key
        and settings.minio_secret_key
        and settings.minio_bucket
    )
    missing_storage_keys = _count(
        db,
        select(models.Sbom).where(
            (models.Sbom.storage_key.is_(None)) | (models.Sbom.storage_key == ""),
        ),
    )
    source_sbom_artifacts = _source_sbom_artifact_count(db)
    source_sboms = _count(db, select(models.Sbom).where(models.Sbom.sbom_kind == "source"))
    restore_logs = _recent_restore_logs(db)
    return [
        _restore_check(
            "object_storage",
            "ok" if storage_configured else "fail",
            1 if storage_configured else 0,
            f"Object storage bucket setting: {settings.minio_bucket}",
        ),
        _restore_check(
            "sbom_storage_keys",
            "ok" if not missing_storage_keys else "fail",
            missing_storage_keys,
            "SBOM records without a storage key",
        ),
        _restore_check(
            "source_sbom_artifacts",
            "ok" if source_sbom_artifacts >= source_sboms else "warn",
            source_sbom_artifacts,
            f"Source SBOM artifacts available for {source_sboms} source SBOMs",
        ),
        _restore_check(
            "restore_exercise_30d",
            "ok" if restore_logs else "warn",
            len(restore_logs),
            "Restore verification audit logs in the last 30 days",
        ),
    ]


@router.get("/weekly-review", response_model=list[schemas.WeeklyReviewOut])
def weekly_review(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    upcoming_cutoff = now + timedelta(days=7)
    medium_open = _count(
        db,
        select(models.Finding).where(
            models.Finding.status == models.FindingStatus.open,
            models.Finding.severity == models.Severity.medium,
        ),
    )
    expired_vex = sum(1 for vex in db.scalars(select(models.VexStatement)) if _before(vex.review_date, now))
    upcoming_vex = sum(
        1
        for vex in db.scalars(select(models.VexStatement))
        if not _before(vex.review_date, now) and _before(vex.review_date, upcoming_cutoff)
    )
    false_positive = _count(
        db,
        select(models.Finding).where(models.Finding.status == models.FindingStatus.false_positive),
    )
    failed_ai_fix = _count(
        db,
        select(models.RemediationAction).where(
            models.RemediationAction.action_type == ACTION_TYPE_AI_FIX,
            models.RemediationAction.status == "failed",
        ),
    )
    scanner_version_missing = _count(
        db,
        select(models.Scan).where(models.Scan.tool.is_not(None), models.Scan.tool_version.is_(None)),
    )
    stale_prs = stale_remediation_count(db)
    return [
        _weekly("medium_findings", "warn", medium_open, "Open medium findings awaiting weekly review"),
        _weekly("expired_vex", "warn", expired_vex, "VEX statements past review date"),
        _weekly("upcoming_vex", "warn", upcoming_vex, "VEX statements due in the next 7 days"),
        _weekly("false_positive", "warn", false_positive, "False positive findings to sample review"),
        _weekly("auto_fix_failed", "fail", failed_ai_fix, "AI fix remediation actions that failed"),
        _weekly("scanner_version_missing", "warn", scanner_version_missing, "Scanner runs without tool version"),
        _weekly("stale_prs", "fail", stale_prs, "Stale or failed remediation actions"),
    ]


@router.get("/manual-actions", response_model=schemas.CursorPage)
def list_manual_actions(
    limit: int = 50,
    action: str | None = None,
    actor: str | None = None,
    days: int = 30,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = manual_action_items(db, days=days)
    if action:
        items = [item for item in items if item["action"] == action]
    if actor:
        items = [item for item in items if item["actor"] == actor]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/failure-signals", response_model=schemas.CursorPage)
def list_failure_signals(
    limit: int = 50,
    signal_type: str | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = failure_signal_items(db)
    if signal_type:
        items = [item for item in items if item["signal_type"] == signal_type]
    if source:
        items = [item for item in items if item["source"] == source]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/worker-posture", response_model=list[schemas.WorkerPostureOut])
def worker_posture(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    return worker_posture_items(db, settings)


@router.get("/scan-targets", response_model=list[schemas.ScanTargetOut])
def scan_targets(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return scan_target_items(db)


def failure_signal_count(db: Session) -> int:
    return len(failure_signal_items(db))


def manual_action_count(db: Session, days: int = 30) -> int:
    return len(manual_action_items(db, days=days))


def manual_action_items(db: Session, days: int = 30) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())
    items = []
    for audit_log in db.scalars(stmt):
        if _before(audit_log.created_at, cutoff):
            continue
        reason = _manual_action_reason(audit_log)
        if not reason:
            continue
        items.append(
            schemas.ManualActionOut(
                id=audit_log.id,
                actor=audit_log.actor,
                role=audit_log.role,
                action=audit_log.action,
                resource_type=audit_log.resource_type,
                resource_id=audit_log.resource_id,
                metadata_json=audit_log.metadata_json,
                created_at=audit_log.created_at,
                reason=reason,
            ).model_dump(mode="json")
        )
    return items


def failure_signal_items(db: Session) -> list[dict]:
    items = []
    items.extend(_job_failure_signals(db))
    items.extend(_scan_failure_signals(db))
    items.extend(_remediation_failure_signals(db))
    items.extend(_notification_failure_signals(db))
    return sorted(items, key=lambda item: item["created_at"], reverse=True)


def worker_posture_items(db: Session, settings: Settings) -> list[schemas.WorkerPostureOut]:
    now = datetime.now(timezone.utc)
    stale_running = [
        job
        for job in db.scalars(select(models.Job).where(models.Job.status == models.JobStatus.running))
        if job.started_at and _before(job.started_at, now - timedelta(seconds=settings.worker_job_timeout_seconds))
    ]
    timed_out = list(db.scalars(select(models.Job).where(models.Job.status == models.JobStatus.timed_out)))
    isolated_scan_failures = _isolated_scan_failures(db)
    credential_signals = [
        item for item in failure_signal_items(db) if item["signal_type"] == "private_auth_failure"
    ]
    return [
        _worker_check(
            "job_timeout",
            "ok" if settings.worker_job_timeout_seconds > 0 else "fail",
            settings.worker_job_timeout_seconds,
            f"worker_job_timeout_seconds={settings.worker_job_timeout_seconds}",
        ),
        _worker_check("stale_running_jobs", "fail" if stale_running else "ok", len(stale_running), "Running jobs older than worker timeout"),
        _worker_check("timed_out_jobs", "fail" if timed_out else "ok", len(timed_out), "Jobs with timed_out status"),
        _worker_check("isolated_scan_failures", "warn" if isolated_scan_failures else "ok", len(isolated_scan_failures), "Failed scans for restricted or isolated lane applications"),
        _worker_check("credential_failure_signals", "fail" if credential_signals else "ok", len(credential_signals), "Failure signals mentioning auth or credentials"),
    ]


def scan_target_items(db: Session) -> list[schemas.ScanTargetOut]:
    scans = list(db.scalars(select(models.Scan)))
    total = len(scans)
    succeeded = sum(1 for scan in scans if scan.status == models.ScanStatus.succeeded)
    failed = sum(1 for scan in scans if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out})
    partial = sum(1 for scan in scans if scan.status == models.ScanStatus.partially_succeeded)
    stale = _stale_active_application_count(db)
    success_rate = _percent(succeeded, total)
    return [
        _scan_target(
            "daily_scan_success_rate",
            "ok" if success_rate >= 95.0 else "warn",
            succeeded,
            95.0,
            success_rate,
            f"Succeeded scans among {total} scan records",
        ),
        _scan_target("failed_scans", "fail" if failed else "ok", failed, None, None, "Failed or timed out scan records"),
        _scan_target("partial_scans", "warn" if partial else "ok", partial, None, None, "Partially succeeded scan records"),
        _scan_target("stale_active_applications", "warn" if stale else "ok", stale, None, None, "Active applications without a scan in the last 30 days"),
    ]


def manual_workload_count(db: Session) -> int:
    return sum(row.count for row in _workload_rows(db))


def _workload_rows(db: Session) -> list[schemas.OperationalWorkloadOut]:
    open_findings = _count(db, select(models.Finding).where(models.Finding.status == models.FindingStatus.open))
    manual_scans = _count(db, select(models.Scan).where(models.Scan.trigger_type == models.TriggerType.manual))
    manual_jobs = _count(db, select(models.AuditLog).where(models.AuditLog.action == "job.create"))
    failed_remediation = _count(db, select(models.RemediationAction).where(models.RemediationAction.status == "failed"))
    close_failed_issues = _count(
        db,
        select(models.RemediationAction).where(
            models.RemediationAction.action_type == "github_issue",
            models.RemediationAction.status == "close_failed",
        ),
    )
    return [
        _workload("open_findings", open_findings, "warn", "Open findings requiring triage or remediation"),
        _workload("manual_scans", manual_scans, "warn", "Scans triggered manually"),
        _workload("manual_jobs", manual_jobs, "warn", "Jobs created directly by an operator"),
        _workload("failed_remediation_actions", failed_remediation, "fail", "Remediation actions that failed"),
        _workload("close_failed_issue_actions", close_failed_issues, "fail", "GitHub issue close attempts that failed"),
    ]


def _job_failure_signals(db: Session) -> list[dict]:
    items = []
    jobs = db.scalars(
        select(models.Job).where(models.Job.status.in_([models.JobStatus.failed, models.JobStatus.timed_out]))
    )
    for job in jobs:
        detail = job.last_error or job.status.value
        items.append(_failure_signal(_classify_failure(detail, default="worker_failure"), "job", str(job.id), job.status.value, detail, job.created_at))
    return items


def _scan_failure_signals(db: Session) -> list[dict]:
    items = []
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Scan.status.in_([models.ScanStatus.failed, models.ScanStatus.partially_succeeded, models.ScanStatus.timed_out]))
    )
    for scan, application, repository in db.execute(stmt):
        failures = (scan.result_summary or {}).get("scanner_failures") or []
        if isinstance(failures, dict):
            failures = [failures]
        details = [scan.error_message] if scan.error_message else []
        if isinstance(failures, list):
            details.extend(str(failure.get("error") if isinstance(failure, dict) else failure) for failure in failures)
        for detail in details or [scan.status.value]:
            items.append(
                _failure_signal(
                    _classify_failure(detail, default="scanner_failure"),
                    "scan",
                    str(scan.id),
                    scan.status.value,
                    detail,
                    scan.created_at,
                    repository=repository,
                    application=application,
                )
            )
    return items


def _remediation_failure_signals(db: Session) -> list[dict]:
    items = []
    stmt = (
        select(models.RemediationAction, models.Finding, models.Application, models.Repository)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
    )
    for action, _, application, repository in db.execute(stmt):
        metadata = action.metadata_json or {}
        detail = metadata.get("error") or metadata.get("close_error") or metadata.get("validation_error")
        if action.status == "skipped_duplicate":
            detail = metadata.get("skipped_reason") or "Duplicate remediation action suppressed"
            signal_type = "duplicate_suppression"
        elif action.status in {"failed", "close_failed"} or detail:
            signal_type = _classify_failure(str(detail or action.status), default="worker_failure")
        else:
            continue
        items.append(
            _failure_signal(
                signal_type,
                "remediation_action",
                str(action.id),
                action.status,
                str(detail),
                action.updated_at,
                repository=repository,
                application=application,
            )
        )
    return items


def _notification_failure_signals(db: Session) -> list[dict]:
    items = []
    notifications = db.scalars(select(models.Notification).where(models.Notification.status == "failed"))
    for notification in notifications:
        items.append(
            _failure_signal(
                _classify_failure(notification.body, default="worker_failure"),
                "notification",
                str(notification.id),
                notification.status,
                notification.subject,
                notification.created_at,
            )
        )
    return items


def _classify_failure(detail: str | None, default: str) -> str:
    text = (detail or "").lower()
    if "rate limit" in text:
        return "github_rate_limit"
    if "timeout" in text or "timed out" in text:
        return "github_timeout" if "github" in text else "worker_failure"
    if "clone" in text:
        return "clone_failure"
    if "private" in text or "auth" in text or "credential" in text or "401" in text or "403" in text:
        return "private_auth_failure"
    if "scanner" in text or "trivy" in text or "syft" in text or "osv" in text:
        return "scanner_failure"
    if "minio" in text or "s3" in text or "storage" in text or "object" in text:
        return "storage_failure"
    return default


def _failure_signal(
    signal_type: str,
    source: str,
    source_id: str,
    status: str,
    detail: str,
    created_at: datetime,
    repository: models.Repository | None = None,
    application: models.Application | None = None,
) -> dict:
    return schemas.FailureSignalOut(
        signal_type=signal_type,
        source=source,
        source_id=source_id,
        status=status,
        detail=detail,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        created_at=created_at,
    ).model_dump(mode="json")


def _readiness(check: str, configured: bool, detail: str) -> schemas.OperationsReadinessOut:
    return schemas.OperationsReadinessOut(
        check=check,
        status="ok" if configured else "warn",
        configured=configured,
        detail=detail,
    )


def _daily_check(check: str, status: str, count: int, detail: str) -> schemas.DailyOperationCheckOut:
    return schemas.DailyOperationCheckOut(check=check, status=status, count=count, detail=detail)


def _workload(item: str, count: int, nonzero_status: str, detail: str) -> schemas.OperationalWorkloadOut:
    return schemas.OperationalWorkloadOut(
        item=item,
        count=count,
        status=nonzero_status if count else "ok",
        detail=detail,
    )


def _worker_check(check: str, status: str, count: int, detail: str) -> schemas.WorkerPostureOut:
    return schemas.WorkerPostureOut(check=check, status=status, count=count, detail=detail)


def _scan_target(
    check: str,
    status: str,
    count: int,
    target_percent: float | None,
    actual_percent: float | None,
    detail: str,
) -> schemas.ScanTargetOut:
    return schemas.ScanTargetOut(
        check=check,
        status=status,
        count=count,
        target_percent=target_percent,
        actual_percent=actual_percent,
        detail=detail,
    )


def _backup_check(check: str, status: str, count: int, detail: str) -> schemas.BackupReadinessOut:
    return schemas.BackupReadinessOut(check=check, status=status, count=count, detail=detail)


def _restore_check(check: str, status: str, count: int, detail: str) -> schemas.RestoreReadinessOut:
    return schemas.RestoreReadinessOut(check=check, status=status, count=count, detail=detail)


def _weekly(item: str, nonzero_status: str, count: int, detail: str) -> schemas.WeeklyReviewOut:
    return schemas.WeeklyReviewOut(
        item=item,
        status=nonzero_status if count else "ok",
        count=count,
        detail=detail,
    )


def _count(db: Session, stmt) -> int:
    subquery = stmt.subquery()
    return db.scalar(select(func.count()).select_from(subquery)) or 0


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def _source_sbom_artifact_count(db: Session) -> int:
    count = 0
    scans = db.scalars(select(models.Scan))
    for scan in scans:
        artifacts = (scan.result_summary or {}).get("artifacts") or {}
        if isinstance(artifacts, dict) and isinstance(artifacts.get("source_sbom"), dict):
            if artifacts["source_sbom"].get("storage_key"):
                count += 1
    return count


def _recent_restore_logs(db: Session) -> list[models.AuditLog]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    actions = {"backup.restore", "restore.verify", "backup.restore.verify"}
    return [
        log
        for log in db.scalars(select(models.AuditLog).where(models.AuditLog.action.in_(actions)))
        if _after_cutoff(log.created_at, cutoff)
    ]


def _isolated_scan_failures(db: Session) -> list[models.Scan]:
    scans = db.scalars(
        select(models.Scan)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(
            models.Scan.status.in_([models.ScanStatus.failed, models.ScanStatus.timed_out]),
            (
                models.Repository.provider == models.RepositoryProvider.isolated
            )
            | (
                models.Repository.source_classification.in_(
                    [models.SourceClassification.restricted, models.SourceClassification.isolated]
                )
            ),
        )
    )
    return list(scans)


def _stale_active_application_count(db: Session) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    count = 0
    for application in db.scalars(select(models.Application).where(models.Application.lifecycle != models.Lifecycle.archived)):
        latest = db.scalar(
            select(models.Scan)
            .where(models.Scan.application_id == application.id)
            .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
        )
        if latest is None or _before(latest.created_at, cutoff):
            count += 1
    return count


def _manual_action_reason(audit_log: models.AuditLog) -> str | None:
    manual_actions = {
        "scan.create": "manual_scan",
        "job.create": "manual_job",
        "repository.scan.enqueue": "manual_scan_enqueue",
        "finding.github_issue.enqueue": "manual_issue",
    }
    if audit_log.action in manual_actions:
        return manual_actions[audit_log.action]
    metadata = audit_log.metadata_json or {}
    searchable = f"{audit_log.action} {metadata}".lower()
    if "dependency" in searchable:
        return "manual_dependency_update"
    if "manual" in searchable:
        return "manual"
    return None


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


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
