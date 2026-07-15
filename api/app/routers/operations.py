from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.governance import runtime_eol_items
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


@router.get("/monthly-review", response_model=list[schemas.MonthlyReviewOut])
def monthly_review(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return monthly_review_items(db)


@router.get("/toolchain-posture", response_model=list[schemas.ToolchainPostureOut])
def toolchain_posture(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return toolchain_posture_items(db)


@router.get("/phase-readiness", response_model=list[schemas.PhaseReadinessOut])
def phase_readiness(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return phase_readiness_items(db)


@router.get("/control-evidence", response_model=list[schemas.ControlEvidenceOut])
def control_evidence(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return control_evidence_items(db)


@router.get("/rollback-readiness", response_model=list[schemas.RollbackReadinessOut])
def rollback_readiness(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return rollback_readiness_items(db)


@router.get("/queue-pressure", response_model=list[schemas.QueuePressureOut])
def queue_pressure(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return queue_pressure_items(db)


@router.get("/scheduler-drift", response_model=schemas.CursorPage)
def list_scheduler_drift(
    limit: int = 50,
    drift_type: str | None = None,
    job_type: models.JobType | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scheduler_drift_items(db)
    if drift_type:
        items = [item for item in items if item["drift_type"] == drift_type]
    if job_type:
        items = [item for item in items if item["job_type"] == job_type.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/credential-failures", response_model=schemas.CursorPage)
def list_credential_failures(
    limit: int = 50,
    source: str | None = None,
    failure_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = credential_failure_items(db)
    if source:
        items = [item for item in items if item["source"] == source]
    if failure_type:
        items = [item for item in items if item["failure_type"] == failure_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def failure_signal_count(db: Session) -> int:
    return len(failure_signal_items(db))


def monthly_review_count(db: Session) -> int:
    return sum(item.count for item in monthly_review_items(db) if item.status != "ok")


def phase_readiness_count(db: Session) -> int:
    return sum(item.count for item in phase_readiness_items(db) if item.status != "ok")


def control_evidence_count(db: Session) -> int:
    return sum(item.count for item in control_evidence_items(db) if item.status != "ok")


def rollback_readiness_count(db: Session) -> int:
    return sum(item.count for item in rollback_readiness_items(db) if item.status != "ok")


def queue_pressure_count(db: Session) -> int:
    return sum(item.stale_count + item.overdue_count + item.retry_exhausted_count for item in queue_pressure_items(db))


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


def monthly_review_items(db: Session) -> list[schemas.MonthlyReviewOut]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    scans = list(db.scalars(select(models.Scan)))
    scan_success_rate = _percent(
        sum(1 for scan in scans if scan.status == models.ScanStatus.succeeded),
        len(scans),
    )
    expired_vex = sum(1 for vex in db.scalars(select(models.VexStatement)) if _before(vex.review_date, now))
    accepted_risk = _count(
        db,
        select(models.Finding).where(models.Finding.status == models.FindingStatus.accepted_risk),
    )
    scanner_version_missing = _count(
        db,
        select(models.Scan).where(models.Scan.tool.is_not(None), models.Scan.tool_version.is_(None)),
    )
    runtime_eol = len(runtime_eol_items(db))
    storage_cleanup = len(list_storage_cleanup_candidates(db=db, _=None).items)
    restore_logs = _recent_restore_logs(db)
    stale_prs = stale_remediation_count(db)
    recent_scans = sum(1 for scan in scans if _after_cutoff(scan.created_at, cutoff))
    return [
        _monthly("vex_reassessment", "warn", expired_vex, "Expired VEX statements to reassess"),
        _monthly("risk_acceptance_reassessment", "warn", accepted_risk, "Accepted-risk findings to sample review"),
        _monthly("tool_version_review", "warn", scanner_version_missing, "Scanner runs without tool version"),
        _monthly("runtime_eol_review", "warn", runtime_eol, "Runtime or component EOL review items"),
        _monthly(
            "scan_success_rate",
            "warn" if scan_success_rate < 95.0 else "ok",
            int(scan_success_rate),
            f"Scan success rate is {scan_success_rate}% across {len(scans)} records",
            status_by_count=False,
        ),
        _monthly("mttr_review", "ok", _resolved_last_30d_count(db, cutoff), "Resolved findings in the last 30 days"),
        _monthly("storage_cleanup", "warn", storage_cleanup, "Storage cleanup candidates awaiting monthly review"),
        _monthly(
            "restore_exercise",
            "warn" if not restore_logs else "ok",
            len(restore_logs),
            "Restore verification audit logs in the last 30 days",
            status_by_count=False,
        ),
        _monthly("stale_pr_review", "fail", stale_prs, "Stale or failed remediation actions"),
        _monthly("recent_scan_volume", "ok" if recent_scans else "warn", recent_scans, "Scan records created in the last 30 days"),
    ]


def toolchain_posture_items(db: Session) -> list[schemas.ToolchainPostureOut]:
    scans = list(db.scalars(select(models.Scan)))
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    version_missing = sum(1 for scan in scans if scan.tool and not scan.tool_version)
    stale_tools = {
        tool
        for tool in {scan.tool for scan in scans if scan.tool}
        if not any(scan.tool == tool and _after_cutoff(scan.created_at, cutoff) for scan in scans)
    }
    failure_count = sum(
        1
        for scan in scans
        if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out, models.ScanStatus.partially_succeeded}
    )
    runtime_count = len(runtime_eol_items(db))
    return [
        _toolchain("scanner_version_missing", "warn" if version_missing else "ok", version_missing, "Scanner runs without tool version"),
        _toolchain("stale_scanner_tools", "warn" if stale_tools else "ok", len(stale_tools), "Scanner tools not seen in the last 30 days"),
        _toolchain("scanner_failure_records", "fail" if failure_count else "ok", failure_count, "Failed, timed out, or partial scanner runs"),
        _toolchain("runtime_eol_items", "warn" if runtime_count else "ok", runtime_count, "Runtime EOL review items"),
    ]


def phase_readiness_items(db: Session) -> list[schemas.PhaseReadinessOut]:
    repositories = list(db.scalars(select(models.Repository)))
    applications = list(db.scalars(select(models.Application)))
    scans = list(db.scalars(select(models.Scan)))
    findings = list(db.scalars(select(models.Finding)))
    actions = list(db.scalars(select(models.RemediationAction)))
    active_applications = [app for app in applications if app.lifecycle != models.Lifecycle.archived]
    active_sbom_app_ids = set(
        db.scalars(
            select(models.Sbom.application_id).where(
                models.Sbom.active.is_(True),
                models.Sbom.sbom_kind == "source",
            )
        )
    )
    latest_scan_by_app = _latest_scan_by_application(scans)
    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stale_apps = sum(
        1
        for app in active_applications
        if app.id not in latest_scan_by_app
        or _before(latest_scan_by_app[app.id].created_at, stale_cutoff)
    )
    open_critical_high = sum(
        1
        for finding in findings
        if finding.status == models.FindingStatus.open
        and finding.severity in {models.Severity.critical, models.Severity.high}
    )
    fixed_without_action = _fixed_without_issue_or_pr_count(db)
    missing_owner = sum(1 for app in active_applications if not app.owner)
    missing_sbom = sum(1 for app in active_applications if app.id not in active_sbom_app_ids)
    failed_scans = sum(
        1
        for scan in scans
        if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out, models.ScanStatus.partially_succeeded}
    )
    validation_missing = sum(
        1
        for action in actions
        if action.status in {"created", "running", "pending", "open", "queued"}
        and (action.metadata_json or {}).get("validation_status") != "succeeded"
    )
    vex_missing = sum(1 for vex in db.scalars(select(models.VexStatement)) if not vex.approved_by or not vex.review_date)
    isolated_repositories = sum(
        1
        for repo in repositories
        if repo.provider == models.RepositoryProvider.isolated
        or repo.source_classification in {models.SourceClassification.restricted, models.SourceClassification.isolated}
    )
    auto_merge_blocked = sum(1 for action in actions if action.action_type == ACTION_TYPE_AI_FIX and action.status in {"failed", "blocked"})
    return [
        _phase("phase_0", "repository_visibility", sum(1 for repo in repositories if not repo.visibility), "Repositories without visibility"),
        _phase("phase_1", "api_inventory", 0 if repositories or applications else 1, "Repository or application inventory exists"),
        _phase("phase_2", "repository_sync", sum(1 for repo in repositories if not repo.last_synced_at), "Repositories without sync timestamp"),
        _phase("phase_3", "application_detection", sum(1 for repo in repositories if not any(app.repository_id == repo.id for app in applications)), "Repositories without detected applications"),
        _phase("phase_4", "sbom_coverage", missing_sbom, "Active applications without active source SBOM"),
        _phase("phase_5", "scan_health", failed_scans + stale_apps, "Failed, partial, timed out, or stale scans"),
        _phase("phase_6", "risk_notification", open_critical_high, "Open critical/high findings requiring notification and response"),
        _phase("phase_7", "issue_pr_rescan", fixed_without_action + validation_missing, "Fixable findings without action or validation"),
        _phase("phase_8", "vex_governance", vex_missing, "VEX statements missing approval or review date"),
        _phase("phase_9", "rollout_owner_sbom", missing_owner + missing_sbom, "Active application owner or SBOM rollout gaps"),
        _phase("phase_10", "isolated_lane", 0 if isolated_repositories else 1, "Restricted or isolated lane inventory exists"),
        _phase("phase_11", "auto_merge_pilot", auto_merge_blocked, "Blocked or failed AI fix actions before auto-merge pilot"),
    ]


def control_evidence_items(db: Session) -> list[schemas.ControlEvidenceOut]:
    scans = list(db.scalars(select(models.Scan)))
    sboms = list(db.scalars(select(models.Sbom)))
    findings = list(db.scalars(select(models.Finding)))
    actions = list(db.scalars(select(models.RemediationAction)))
    notifications = list(db.scalars(select(models.Notification)))
    vex_statements = list(db.scalars(select(models.VexStatement)))
    audit_logs = list(db.scalars(select(models.AuditLog)))

    source_sboms = [sbom for sbom in sboms if sbom.active and sbom.sbom_kind == "source"]
    source_sbom_artifacts = _source_sbom_artifact_count(db)
    missing_scan_summary = sum(1 for scan in scans if not (scan.result_summary or {}))
    open_critical_high = [
        finding
        for finding in findings
        if finding.status == models.FindingStatus.open
        and finding.severity in {models.Severity.critical, models.Severity.high}
    ]
    notified_finding_ids = {
        _metadata_uuid(notification.metadata_json, "finding_id")
        for notification in notifications
        if notification.status == "sent"
    }
    notified_finding_ids.discard(None)
    unnotified = sum(1 for finding in open_critical_high if finding.id not in notified_finding_ids)
    fixable = [finding for finding in findings if finding.fixed_version and finding.status == models.FindingStatus.open]
    remediated_finding_ids = {
        action.finding_id
        for action in actions
        if action.action_type == "github_issue" or action.branch or action.url or (action.metadata_json or {}).get("pull_request_url")
    }
    missing_issue_pr = sum(1 for finding in fixable if finding.id not in remediated_finding_ids)
    validation_missing = sum(
        1
        for action in actions
        if action.status in {"created", "running", "pending", "open", "queued"}
        and (action.metadata_json or {}).get("validation_status") != "succeeded"
    )
    unresolved_closures = _resolved_without_closure_count(db)
    incomplete_vex = sum(1 for vex in vex_statements if not vex.approved_by or not vex.review_date)
    missing_audit = (
        sum(1 for vex in vex_statements if not _has_audit_log(audit_logs, "vex", str(vex.id)))
        + sum(1 for action in actions if not _has_audit_log(audit_logs, "remediation_action", str(action.id)))
    )

    return [
        _control_evidence(
            "source_sbom_artifacts",
            "warn" if source_sbom_artifacts < len(source_sboms) else "ok",
            max(len(source_sboms) - source_sbom_artifacts, 0),
            "Active source SBOMs without recorded storage artifact",
        ),
        _control_evidence("scan_result_summary", "warn" if missing_scan_summary else "ok", missing_scan_summary, "Scans without result summary evidence"),
        _control_evidence("critical_high_notifications", "fail" if unnotified else "ok", unnotified, "Open critical/high findings without sent notification evidence"),
        _control_evidence("issue_or_pr_evidence", "warn" if missing_issue_pr else "ok", missing_issue_pr, "Fixable open findings without issue or PR evidence"),
        _control_evidence("validation_evidence", "warn" if validation_missing else "ok", validation_missing, "Open remediation actions without successful validation evidence"),
        _control_evidence("closure_evidence", "warn" if unresolved_closures else "ok", unresolved_closures, "Resolved findings without closure evidence"),
        _control_evidence("vex_approval_evidence", "warn" if incomplete_vex else "ok", incomplete_vex, "VEX statements without approval or review evidence"),
        _control_evidence("audit_trail_evidence", "warn" if missing_audit else "ok", missing_audit, "VEX or remediation records without audit trail evidence"),
    ]


def rollback_readiness_items(db: Session) -> list[schemas.RollbackReadinessOut]:
    actions = [action for action in db.scalars(select(models.RemediationAction)) if _is_merged_action(action)]
    scans = list(db.scalars(select(models.Scan)))
    audit_logs = list(db.scalars(select(models.AuditLog)))
    rollback_missing = 0
    pr_missing = 0
    branch_missing = 0
    fixed_version_missing = 0
    audit_missing = 0
    validation_missing = 0
    post_merge_scan_missing = 0
    for action in actions:
        metadata = action.metadata_json or {}
        if not (metadata.get("rollback_branch") or metadata.get("rollback_plan") or metadata.get("rollback_commit")):
            rollback_missing += 1
        if not (action.url or metadata.get("pull_request_url") or metadata.get("html_url")):
            pr_missing += 1
        if not action.branch:
            branch_missing += 1
        if not action.fixed_version:
            fixed_version_missing += 1
        if not _has_audit_log(audit_logs, "remediation_action", str(action.id)):
            audit_missing += 1
        validation_scan = _scan_from_metadata(scans, metadata)
        if metadata.get("validation_status") != "succeeded" and validation_scan is None:
            validation_missing += 1
        application_id = _application_id_for_action(db, action)
        if application_id is None or not _has_scan_after(scans, application_id, action.updated_at):
            post_merge_scan_missing += 1
    return [
        _rollback("rollback_metadata", "warn", rollback_missing, "Merged actions without rollback metadata"),
        _rollback("pr_url", "warn", pr_missing, "Merged actions without PR URL evidence"),
        _rollback("branch", "warn", branch_missing, "Merged actions without branch evidence"),
        _rollback("fixed_version", "warn", fixed_version_missing, "Merged actions without fixed version evidence"),
        _rollback("audit_log", "warn", audit_missing, "Merged actions without audit log evidence"),
        _rollback("validation_scan", "fail", validation_missing, "Merged actions without successful validation scan evidence"),
        _rollback("post_merge_scan", "fail", post_merge_scan_missing, "Merged actions without post-merge scan evidence"),
    ]


def queue_pressure_items(db: Session) -> list[schemas.QueuePressureOut]:
    now = datetime.now(timezone.utc)
    jobs = list(db.scalars(select(models.Job)))
    items = []
    for job_type in models.JobType:
        for status in models.JobStatus:
            rows = [job for job in jobs if job.job_type == job_type and job.status == status]
            if not rows:
                continue
            stale = [
                job
                for job in rows
                if status == models.JobStatus.running
                and job.started_at
                and _before(job.started_at, now - timedelta(hours=24))
            ]
            overdue = [
                job
                for job in rows
                if status == models.JobStatus.queued and _before(job.run_after, now - timedelta(hours=24))
            ]
            retry_exhausted = [
                job
                for job in rows
                if status in {models.JobStatus.failed, models.JobStatus.timed_out, models.JobStatus.cancelled}
                and job.attempts >= job.max_attempts
            ]
            oldest = max(_age_hours(job.created_at, now) for job in rows)
            items.append(
                schemas.QueuePressureOut(
                    job_type=job_type,
                    status=status,
                    count=len(rows),
                    stale_count=len(stale),
                    overdue_count=len(overdue),
                    retry_exhausted_count=len(retry_exhausted),
                    oldest_age_hours=oldest,
                    detail="Job queue pressure by type and status",
                )
            )
    return items


def scheduler_drift_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    recent_cutoff = now - timedelta(hours=24)
    stale_cutoff = now - timedelta(days=30)
    items = []
    latest_jobs = _latest_jobs_by_type(db)
    for job_type in [models.JobType.repository_sync, models.JobType.scan, models.JobType.remediation_validation]:
        job = latest_jobs.get(job_type)
        if job is None or _before(job.created_at, recent_cutoff):
            items.append(
                _scheduler_drift(
                    "missing_recent_job",
                    job_type,
                    None,
                    None,
                    job,
                    1,
                    f"No {job_type.value} job created in the last 24 hours",
                )
            )
    queued = list(
        db.scalars(
            select(models.Job)
            .where(models.Job.status == models.JobStatus.queued)
            .order_by(models.Job.run_after.asc(), models.Job.id.asc())
        )
    )
    for job in queued:
        if _before(job.run_after, recent_cutoff):
            repository = db.get(models.Repository, job.repository_id) if job.repository_id else None
            application = db.get(models.Application, job.application_id) if job.application_id else None
            items.append(_scheduler_drift("overdue_queued_job", job.job_type, application, repository, job, 1, "Queued job is overdue by more than 24 hours"))
    latest_schedule_scans = _latest_schedule_scan_by_application(db)
    for application, repository in db.execute(
        select(models.Application, models.Repository)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Application.lifecycle != models.Lifecycle.archived)
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
    ):
        scan = latest_schedule_scans.get(application.id)
        if scan is None or _before(scan.created_at, stale_cutoff):
            items.append(_scheduler_drift("missing_scheduled_scan", models.JobType.scan, application, repository, None, 1, "Active application has no scheduled scan in the last 30 days"))
    return items


def credential_failure_items(db: Session) -> list[dict]:
    items = []
    for item in failure_signal_items(db):
        if _credential_failure_match(item["signal_type"], item["detail"]):
            items.append(_credential_failure(item["signal_type"], item))
    for audit_log in db.scalars(select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())):
        detail = f"{audit_log.action} {audit_log.metadata_json or {}}"
        failure_type = _classify_failure(detail, default="worker_failure")
        if _credential_failure_match(failure_type, detail):
            items.append(
                schemas.CredentialFailureOut(
                    failure_type=failure_type,
                    source="audit_log",
                    source_id=str(audit_log.id),
                    status=audit_log.action,
                    detail=detail,
                    created_at=audit_log.created_at,
                ).model_dump(mode="json")
            )
    return sorted(items, key=lambda item: item["created_at"], reverse=True)


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
        detail = " ".join(part for part in [notification.subject, notification.body] if part)
        items.append(
            _failure_signal(
                _classify_failure(detail, default="worker_failure"),
                "notification",
                str(notification.id),
                notification.status,
                detail,
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


def _monthly(
    item: str,
    nonzero_status: str,
    count: int,
    detail: str,
    status_by_count: bool = True,
) -> schemas.MonthlyReviewOut:
    return schemas.MonthlyReviewOut(
        item=item,
        status=nonzero_status if (count or not status_by_count) else "ok",
        count=count,
        detail=detail,
    )


def _toolchain(check: str, status: str, count: int, detail: str) -> schemas.ToolchainPostureOut:
    return schemas.ToolchainPostureOut(check=check, status=status, count=count, detail=detail)


def _phase(phase: str, check: str, count: int, detail: str) -> schemas.PhaseReadinessOut:
    return schemas.PhaseReadinessOut(
        phase=phase,
        check=check,
        status="warn" if count else "ok",
        count=count,
        detail=detail,
    )


def _control_evidence(check: str, status: str, count: int, detail: str) -> schemas.ControlEvidenceOut:
    return schemas.ControlEvidenceOut(check=check, status=status, count=count, detail=detail)


def _rollback(check: str, nonzero_status: str, count: int, detail: str) -> schemas.RollbackReadinessOut:
    return schemas.RollbackReadinessOut(
        check=check,
        status=nonzero_status if count else "ok",
        count=count,
        detail=detail,
    )


def _scheduler_drift(
    drift_type: str,
    job_type: models.JobType,
    application: models.Application | None,
    repository: models.Repository | None,
    job: models.Job | None,
    count: int,
    detail: str,
) -> dict:
    return schemas.SchedulerDriftOut(
        drift_type=drift_type,
        job_type=job_type,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        latest_job_id=job.id if job else None,
        latest_job_status=job.status if job else None,
        latest_job_created_at=job.created_at if job else None,
        count=count,
        detail=detail,
    ).model_dump(mode="json")


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


def _resolved_without_closure_count(db: Session) -> int:
    closed_finding_ids = {
        action.finding_id
        for action in db.scalars(select(models.RemediationAction))
        if action.action_type == "github_issue"
        and (action.status == "closed" or bool((action.metadata_json or {}).get("github_issue_closed_at")))
    }
    return sum(
        1
        for finding in db.scalars(select(models.Finding).where(models.Finding.status == models.FindingStatus.resolved))
        if finding.id not in closed_finding_ids
    )


def _metadata_uuid(metadata: dict | None, key: str):
    value = (metadata or {}).get(key)
    if value is None:
        return None
    try:
        from uuid import UUID

        return UUID(str(value))
    except ValueError:
        return None


def _has_audit_log(audit_logs: list[models.AuditLog], resource_type: str, resource_id: str) -> bool:
    return any(log.resource_type == resource_type and log.resource_id == resource_id for log in audit_logs)


def _is_merged_action(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    return action.status in {"merged", "succeeded", "closed"} or bool(metadata.get("merged_at"))


def _scan_from_metadata(scans: list[models.Scan], metadata: dict) -> models.Scan | None:
    scan_id = _metadata_uuid(metadata, "validation_scan_id")
    if scan_id is None:
        return None
    return next((scan for scan in scans if scan.id == scan_id), None)


def _application_id_for_action(db: Session, action: models.RemediationAction):
    finding = db.get(models.Finding, action.finding_id)
    return finding.application_id if finding else None


def _has_scan_after(scans: list[models.Scan], application_id, created_at: datetime) -> bool:
    return any(scan.application_id == application_id and _after_cutoff(scan.created_at, created_at) for scan in scans)


def _age_hours(value: datetime, now: datetime) -> int:
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    elif now.tzinfo is None:
        value = value.replace(tzinfo=None)
    return max(int((now - value).total_seconds() // 3600), 0)


def _latest_jobs_by_type(db: Session) -> dict[models.JobType, models.Job]:
    latest = {}
    jobs = db.scalars(select(models.Job).order_by(models.Job.created_at.desc(), models.Job.id.desc()))
    for job in jobs:
        latest.setdefault(job.job_type, job)
    return latest


def _latest_schedule_scan_by_application(db: Session) -> dict:
    latest = {}
    scans = db.scalars(
        select(models.Scan)
        .where(models.Scan.trigger_type == models.TriggerType.schedule)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
    )
    for scan in scans:
        latest.setdefault(scan.application_id, scan)
    return latest


def _credential_failure_match(failure_type: str, detail: str | None) -> bool:
    text = f"{failure_type} {detail or ''}".lower()
    return any(token in text for token in ["auth", "credential", "token", "permission", "401", "403", "rate limit"])


def _credential_failure(failure_type: str, item: dict) -> dict:
    return schemas.CredentialFailureOut(
        failure_type=failure_type,
        source=item["source"],
        source_id=item["source_id"],
        status=item["status"],
        detail=item["detail"],
        repository_id=item.get("repository_id"),
        repository_owner=item.get("repository_owner"),
        repository_name=item.get("repository_name"),
        application_id=item.get("application_id"),
        application_name=item.get("application_name"),
        created_at=item["created_at"],
    ).model_dump(mode="json")


def _recent_restore_logs(db: Session) -> list[models.AuditLog]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    actions = {"backup.restore", "restore.verify", "backup.restore.verify"}
    return [
        log
        for log in db.scalars(select(models.AuditLog).where(models.AuditLog.action.in_(actions)))
        if _after_cutoff(log.created_at, cutoff)
    ]


def _latest_scan_by_application(scans: list[models.Scan]) -> dict:
    latest = {}
    for scan in sorted(scans, key=lambda item: (_sort_datetime(item.created_at), item.id), reverse=True):
        latest.setdefault(scan.application_id, scan)
    return latest


def _sort_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=None) if value.tzinfo else value


def _fixed_without_issue_or_pr_count(db: Session) -> int:
    action_finding_ids = set()
    for action in db.scalars(select(models.RemediationAction)):
        metadata = action.metadata_json or {}
        if action.action_type == "github_issue" or action.branch or action.url or metadata.get("pull_request_url"):
            action_finding_ids.add(action.finding_id)
    return sum(
        1
        for finding in db.scalars(
            select(models.Finding).where(
                models.Finding.status == models.FindingStatus.open,
                models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
                models.Finding.fixed_version.is_not(None),
            )
        )
        if finding.id not in action_finding_ids
    )


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


def _resolved_last_30d_count(db: Session, cutoff: datetime) -> int:
    return sum(
        1
        for finding in db.scalars(
            select(models.Finding).where(
                models.Finding.status == models.FindingStatus.resolved,
                models.Finding.resolved_at.is_not(None),
            )
        )
        if finding.resolved_at and _after_cutoff(finding.resolved_at, cutoff)
    )


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
