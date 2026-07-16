from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/quality", tags=["quality"])

OPEN_ACTION_STATUSES = {
    "queued",
    "pending",
    "pending_provider",
    "created",
    "running",
    "in_progress",
    "close_failed",
}


@router.get("/duplicates", response_model=schemas.CursorPage)
def list_duplicate_review(
    limit: int = 50,
    duplicate_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = duplicate_review_items(db)
    if duplicate_type:
        items = [item for item in items if item["duplicate_type"] == duplicate_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/reopen-risk", response_model=schemas.CursorPage)
def list_reopen_risk(
    limit: int = 50,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = reopen_risk_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/false-positive-review", response_model=schemas.CursorPage)
def list_false_positive_review(
    limit: int = 50,
    review_type: str | None = None,
    expired: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = false_positive_review_items(db)
    if review_type:
        items = [item for item in items if item["review_type"] == review_type]
    if expired is not None:
        items = [item for item in items if item["expired"] is expired]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/state-consistency", response_model=schemas.CursorPage)
def list_state_consistency(
    limit: int = 50,
    gap_type: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = state_consistency_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/metadata-completeness", response_model=schemas.CursorPage)
def list_metadata_completeness(
    limit: int = 50,
    gap_type: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = metadata_completeness_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/orphan-evidence", response_model=schemas.CursorPage)
def list_orphan_evidence(
    limit: int = 50,
    gap_type: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = orphan_evidence_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def reopen_risk_count(db: Session) -> int:
    return len(reopen_risk_items(db))


def false_positive_review_count(db: Session) -> int:
    return len(false_positive_review_items(db))


def state_consistency_gap_count(db: Session) -> int:
    return len(state_consistency_items(db))


def metadata_completeness_gap_count(db: Session) -> int:
    return len(metadata_completeness_items(db))


def orphan_evidence_gap_count(db: Session) -> int:
    return len(orphan_evidence_items(db))


def state_consistency_items(db: Session) -> list[dict]:
    items = []
    for finding in db.scalars(select(models.Finding).order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())):
        if finding.status == models.FindingStatus.resolved and finding.resolved_at is None:
            items.append(_state_item("resolved_without_resolved_at", "finding", finding.id, finding.status.value, "Resolved finding has no resolved_at timestamp", finding.updated_at))
        if finding.status in {models.FindingStatus.open, models.FindingStatus.triaged, models.FindingStatus.in_progress} and finding.resolved_at is not None:
            items.append(_state_item("open_with_resolved_at", "finding", finding.id, finding.status.value, "Open finding has resolved_at timestamp", finding.updated_at))
    for job in db.scalars(select(models.Job).order_by(models.Job.updated_at.desc(), models.Job.id.asc())):
        if job.status in {models.JobStatus.succeeded, models.JobStatus.failed, models.JobStatus.cancelled, models.JobStatus.timed_out} and job.completed_at is None:
            items.append(_state_item("terminal_without_completed_at", "job", job.id, job.status.value, "Terminal job has no completed_at timestamp", job.updated_at))
    for notification in db.scalars(select(models.Notification).order_by(models.Notification.created_at.desc(), models.Notification.id.asc())):
        if notification.status == "sent" and notification.sent_at is None:
            items.append(_state_item("sent_without_sent_at", "notification", notification.id, notification.status, "Sent notification has no sent_at timestamp", notification.created_at))
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.updated_at.desc(), models.RemediationAction.id.asc())):
        metadata = action.metadata_json or {}
        if action.status in {"closed", "resolved", "merged"} and not (metadata.get("closed_at") or metadata.get("github_issue_closed_at") or metadata.get("merged_at")):
            items.append(_state_item("closed_without_close_evidence", "remediation_action", action.id, action.status, "Closed remediation action has no close evidence", action.updated_at))
    return items


def metadata_completeness_items(db: Session) -> list[dict]:
    items = []
    applications = {app.id: app for app in db.scalars(select(models.Application))}
    repositories = {repo.id: repo for repo in db.scalars(select(models.Repository))}
    for scan in db.scalars(select(models.Scan).order_by(models.Scan.created_at.desc(), models.Scan.id.asc())):
        app = applications.get(scan.application_id)
        repo = repositories.get(app.repository_id) if app else None
        summary = scan.result_summary or {}
        if not scan.application_id:
            items.append(_metadata_item("missing_application_context", "scan", scan.id, app, repo, "Scan has no application context", scan.created_at))
        if not scan.commit_sha and scan.trigger_type in {models.TriggerType.push, models.TriggerType.pull_request, models.TriggerType.release, models.TriggerType.remediation_validation}:
            items.append(_metadata_item("missing_commit_context", "scan", scan.id, app, repo, "Repository-triggered scan has no commit context", scan.created_at))
        if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out, models.ScanStatus.partially_succeeded} and not (scan.error_message or summary.get("scanner_failures")):
            items.append(_metadata_item("missing_error_context", "scan", scan.id, app, repo, "Unsuccessful scan has no error context", scan.created_at))
    for job in db.scalars(select(models.Job).order_by(models.Job.created_at.desc(), models.Job.id.asc())):
        app = applications.get(job.application_id) if job.application_id else None
        repo = repositories.get(job.repository_id) if job.repository_id else (repositories.get(app.repository_id) if app else None)
        payload = job.payload or {}
        if job.job_type in {models.JobType.scan, models.JobType.remediation_validation, models.JobType.issue_create} and not (job.application_id or payload.get("application_id")):
            items.append(_metadata_item("missing_application_context", "job", job.id, app, repo, "Job payload has no application context", job.created_at))
        if job.status in {models.JobStatus.failed, models.JobStatus.timed_out} and not (job.last_error or payload.get("error")):
            items.append(_metadata_item("missing_error_context", "job", job.id, app, repo, "Failed job has no error context", job.created_at))
    for notification in db.scalars(select(models.Notification).order_by(models.Notification.created_at.desc(), models.Notification.id.asc())):
        finding = _finding_from_notification(db, notification)
        app, repo = _finding_application_repository(db, finding)
        if finding is None:
            items.append(_metadata_item("missing_finding_context", "notification", notification.id, app, repo, "Notification metadata has no finding context", notification.created_at))
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())):
        finding = db.get(models.Finding, action.finding_id)
        app, repo = _finding_application_repository(db, finding)
        metadata = action.metadata_json or {}
        if not (action.provider_id or action.url or metadata.get("github_issue_url") or metadata.get("pull_request_url")):
            items.append(_metadata_item("missing_external_reference", "remediation_action", action.id, app, repo, "Remediation action has no external reference", action.created_at))
    return items


def orphan_evidence_items(db: Session) -> list[dict]:
    items = []
    active_component_ids = set(
        db.scalars(
            select(models.SbomComponent.component_id)
            .join(models.Sbom, models.SbomComponent.sbom_id == models.Sbom.id)
            .where(models.Sbom.active.is_(True))
        )
    )
    for component in db.scalars(select(models.Component).order_by(models.Component.name.asc(), models.Component.id.asc())):
        if component.id not in active_component_ids:
            items.append(_orphan_item("component_without_active_sbom", "component", component.id, None, None, "Component is not referenced by an active SBOM", None))
    vulnerability_ids = set(db.scalars(select(models.Finding.vulnerability_id)))
    for vulnerability in db.scalars(select(models.Vulnerability).order_by(models.Vulnerability.external_id.asc(), models.Vulnerability.id.asc())):
        if vulnerability.id not in vulnerability_ids:
            items.append(_orphan_item("vulnerability_without_finding", "vulnerability", vulnerability.id, None, None, "Vulnerability has no finding evidence", None))
    for notification in db.scalars(select(models.Notification).order_by(models.Notification.created_at.desc(), models.Notification.id.asc())):
        finding = _finding_from_notification(db, notification)
        app, repo = _finding_application_repository(db, finding)
        if finding is None:
            items.append(_orphan_item("notification_without_finding", "notification", notification.id, app, repo, "Notification does not resolve to a finding", notification.created_at))
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())):
        finding = db.get(models.Finding, action.finding_id)
        app, repo = _finding_application_repository(db, finding)
        if finding and finding.status in {models.FindingStatus.resolved, models.FindingStatus.accepted_risk, models.FindingStatus.false_positive} and action.status in OPEN_ACTION_STATUSES:
            items.append(_orphan_item("action_without_active_finding", "remediation_action", action.id, app, repo, "Open remediation action is attached to a non-active finding", action.created_at))
    for audit_log in db.scalars(select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())):
        if audit_log.resource_id and not _audit_resource_exists(db, audit_log.resource_type, audit_log.resource_id):
            items.append(_orphan_item("audit_without_resource", "audit_log", audit_log.id, None, None, "Audit log references a resource that cannot be resolved", audit_log.created_at))
    return items


def duplicate_review_items(db: Session) -> list[dict]:
    items = []
    items.extend(_notification_duplicates(db))
    items.extend(_remediation_duplicates(db))
    items.extend(_skipped_duplicate_actions(db))
    return sorted(items, key=lambda item: (item["duplicate_type"], item["key"])) 


def reopen_risk_items(db: Session) -> list[dict]:
    stmt = (
        select(
            models.Finding,
            models.Application,
            models.Repository,
            models.Component,
            models.Vulnerability,
        )
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status == models.FindingStatus.resolved)
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        scan = db.get(models.Scan, finding.last_seen_scan_id) if finding.last_seen_scan_id else None
        reason = None
        if finding.resolved_at and scan and _after(scan.created_at, finding.resolved_at):
            reason = "seen_after_resolved"
        elif _has_open_same_identity(db, finding):
            reason = "open_same_identity"
        if not reason:
            continue
        items.append(
            schemas.ReopenRiskOut(
                finding_id=finding.id,
                severity=finding.severity,
                status=finding.status,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                resolved_at=finding.resolved_at,
                last_seen_scan_id=scan.id if scan else None,
                last_seen_scan_created_at=scan.created_at if scan else None,
                reason=reason,
            ).model_dump(mode="json")
        )
    return items


def false_positive_review_items(db: Session) -> list[dict]:
    now = datetime.now()
    reopened_ids = {UUID(item["finding_id"]) for item in reopen_risk_items(db)}
    items = []
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status == models.FindingStatus.false_positive)
        .order_by(models.Finding.updated_at.asc(), models.Finding.id.asc())
    )
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        reappeared = finding.id in reopened_ids
        items.append(
            _false_positive_item(
                "finding_false_positive",
                "finding",
                finding,
                application,
                repository,
                component,
                vulnerability,
                None,
                None,
                False,
                reappeared,
                "False positive finding requires periodic review",
            )
        )
    vex_stmt = (
        select(models.VexStatement, models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Finding, models.VexStatement.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.VexStatement.status == models.VexStatus.not_affected)
        .order_by(models.VexStatement.review_date.asc(), models.VexStatement.id.asc())
    )
    for vex, finding, application, repository, component, vulnerability in db.execute(vex_stmt):
        expired = _before(vex.review_date, now)
        reappeared = finding.id in reopened_ids
        review_type = "expired_not_affected_vex" if expired else "not_affected_vex"
        items.append(
            _false_positive_item(
                review_type,
                "vex",
                finding,
                application,
                repository,
                component,
                vulnerability,
                vex.id,
                vex.review_date,
                expired,
                reappeared,
                "VEX not_affected statement requires review",
            )
        )
    return items


def _notification_duplicates(db: Session) -> list[dict]:
    groups: dict[tuple[str, str, str], list[models.Notification]] = {}
    for notification in db.scalars(select(models.Notification)):
        finding_id = str((notification.metadata_json or {}).get("finding_id") or "")
        if not finding_id:
            continue
        key = (finding_id, notification.channel, notification.subject)
        groups.setdefault(key, []).append(notification)

    items = []
    for (finding_id, channel, subject), notifications in groups.items():
        if len(notifications) < 2:
            continue
        finding = _get_finding(db, finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="notification",
                key=f"{finding_id}:{channel}:{subject}",
                count=len(notifications),
                finding_id=finding.id if finding else None,
                channel=channel,
                subject=subject,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Multiple notifications share finding, channel, and subject",
            ).model_dump(mode="json")
        )
    return items


def _remediation_duplicates(db: Session) -> list[dict]:
    groups: dict[tuple[UUID, str], list[models.RemediationAction]] = {}
    stmt = select(models.RemediationAction).where(models.RemediationAction.status.in_(OPEN_ACTION_STATUSES))
    for action in db.scalars(stmt):
        key = (action.finding_id, action.action_type)
        groups.setdefault(key, []).append(action)

    items = []
    for (finding_id, action_type), actions in groups.items():
        if len(actions) < 2:
            continue
        finding = db.get(models.Finding, finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="remediation_action",
                key=f"{finding_id}:{action_type}",
                count=len(actions),
                finding_id=finding_id,
                action_type=action_type,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Multiple open remediation actions share finding and action type",
            ).model_dump(mode="json")
        )
    return items


def _skipped_duplicate_actions(db: Session) -> list[dict]:
    items = []
    stmt = select(models.RemediationAction).where(models.RemediationAction.status == "skipped_duplicate")
    for action in db.scalars(stmt):
        finding = db.get(models.Finding, action.finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="skipped_duplicate",
                key=f"{action.finding_id}:{action.action_type}:{action.id}",
                count=1,
                finding_id=action.finding_id,
                action_type=action.action_type,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Duplicate prevention skipped a remediation action",
            ).model_dump(mode="json")
        )
    return items


def _state_item(gap_type: str, resource_type: str, resource_id: UUID, status: str, detail: str, created_at: datetime) -> dict:
    return schemas.StateConsistencyOut(
        gap_type=gap_type,
        resource_type=resource_type,
        resource_id=str(resource_id),
        status=status,
        detail=detail,
        created_at=created_at,
    ).model_dump(mode="json")


def _metadata_item(
    gap_type: str,
    resource_type: str,
    resource_id: UUID,
    application: models.Application | None,
    repository: models.Repository | None,
    detail: str,
    created_at: datetime,
) -> dict:
    return schemas.MetadataCompletenessOut(
        gap_type=gap_type,
        resource_type=resource_type,
        resource_id=str(resource_id),
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        detail=detail,
        created_at=created_at,
    ).model_dump(mode="json")


def _orphan_item(
    gap_type: str,
    resource_type: str,
    resource_id: UUID,
    application: models.Application | None,
    repository: models.Repository | None,
    detail: str,
    created_at: datetime | None,
) -> dict:
    timestamp = created_at or datetime.now()
    return schemas.OrphanEvidenceOut(
        gap_type=gap_type,
        resource_type=resource_type,
        resource_id=str(resource_id),
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        detail=detail,
        created_at=timestamp,
    ).model_dump(mode="json")


def _finding_from_notification(db: Session, notification: models.Notification) -> models.Finding | None:
    finding_id = (notification.metadata_json or {}).get("finding_id")
    if not finding_id:
        return None
    return _get_finding(db, str(finding_id))


def _audit_resource_exists(db: Session, resource_type: str, resource_id: str) -> bool:
    model_by_type = {
        "repository": models.Repository,
        "application": models.Application,
        "scan": models.Scan,
        "job": models.Job,
        "finding": models.Finding,
        "remediation_action": models.RemediationAction,
        "notification": models.Notification,
        "vex": models.VexStatement,
        "vex_statement": models.VexStatement,
        "sbom": models.Sbom,
        "component": models.Component,
        "vulnerability": models.Vulnerability,
    }
    model = model_by_type.get(resource_type)
    if model is None:
        return False
    try:
        return db.get(model, UUID(str(resource_id))) is not None
    except ValueError:
        return False


def _get_finding(db: Session, finding_id: str) -> models.Finding | None:
    try:
        return db.get(models.Finding, UUID(str(finding_id)))
    except ValueError:
        return None


def _finding_application_repository(
    db: Session, finding: models.Finding | None
) -> tuple[models.Application | None, models.Repository | None]:
    if not finding:
        return None, None
    application = db.get(models.Application, finding.application_id)
    repository = db.get(models.Repository, application.repository_id) if application else None
    return application, repository


def _has_open_same_identity(db: Session, finding: models.Finding) -> bool:
    return bool(
        db.scalar(
            select(models.Finding.id)
            .where(
                models.Finding.id != finding.id,
                models.Finding.application_id == finding.application_id,
                models.Finding.component_id == finding.component_id,
                models.Finding.vulnerability_id == finding.vulnerability_id,
                models.Finding.status.in_(
                    [
                        models.FindingStatus.open,
                        models.FindingStatus.triaged,
                        models.FindingStatus.in_progress,
                    ]
                ),
            )
            .limit(1)
        )
    )


def _after(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value > reference


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _false_positive_item(
    review_type: str,
    source: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    vex_id: UUID | None,
    review_date: datetime | None,
    expired: bool,
    reappeared: bool,
    detail: str,
) -> dict:
    return schemas.FalsePositiveReviewOut(
        review_type=review_type,
        source=source,
        finding_id=finding.id,
        status=finding.status,
        severity=finding.severity,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        vulnerability_external_id=vulnerability.external_id,
        vex_id=vex_id,
        review_date=review_date,
        expired=expired,
        reappeared=reappeared,
        detail=detail,
    ).model_dump(mode="json")
