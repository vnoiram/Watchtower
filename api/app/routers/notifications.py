from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=schemas.CursorPage)
def list_notifications(
    limit: int = 50,
    status: str | None = None,
    channel: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.Notification)
    if status:
        stmt = stmt.where(models.Notification.status == status)
    if channel:
        stmt = stmt.where(models.Notification.channel == channel)
    if severity:
        stmt = stmt.where(models.Notification.severity == severity)
    stmt = stmt.order_by(models.Notification.created_at.desc(), models.Notification.id.asc()).limit(
        min(limit, 100)
    )

    items = []
    for notification in db.execute(stmt).scalars():
        finding = _finding_from_metadata(db, notification.metadata_json)
        application = db.get(models.Application, finding.application_id) if finding else None
        component = db.get(models.Component, finding.component_id) if finding else None
        vulnerability = db.get(models.Vulnerability, finding.vulnerability_id) if finding else None
        items.append(
            schemas.NotificationInventoryOut(
                id=notification.id,
                channel=notification.channel,
                severity=notification.severity,
                subject=notification.subject,
                status=notification.status,
                sent_at=notification.sent_at,
                created_at=notification.created_at,
                finding_id=finding.id if finding else None,
                finding_status=finding.status if finding else None,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                component_name=component.name if component else None,
                vulnerability_external_id=vulnerability.external_id if vulnerability else None,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/slo", response_model=schemas.CursorPage)
def list_notification_slo(
    limit: int = 50,
    breached: bool | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = notification_slo_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if breached is not None:
        items = [item for item in items if item["breached"] is breached]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/digest-readiness", response_model=schemas.CursorPage)
def list_notification_digest_readiness(
    limit: int = 50,
    issue_type: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = notification_digest_readiness_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/retry-posture", response_model=schemas.CursorPage)
def list_notification_retry_posture(
    limit: int = 50,
    gap_type: str | None = None,
    channel: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = notification_retry_posture_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if channel:
        items = [item for item in items if item["channel"] == channel]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def notification_slo_breach_count(db: Session) -> int:
    return sum(1 for item in notification_slo_items(db) if item["breached"])


def notification_retry_gap_count(db: Session) -> int:
    return len(notification_retry_posture_items(db))


def notification_retry_posture_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(hours=24)
    notifications = list(
        db.scalars(select(models.Notification).order_by(models.Notification.created_at.asc(), models.Notification.id.asc()))
    )
    retry_jobs = _notification_retry_jobs(db)
    duplicate_counts = _duplicate_notification_counts(notifications)
    items = []
    for notification in notifications:
        finding = _finding_from_metadata(db, notification.metadata_json)
        application = db.get(models.Application, finding.application_id) if finding else None
        repository = db.get(models.Repository, application.repository_id) if application else None
        retry_job = _retry_job_for_notification(notification, retry_jobs)
        duplicate_count = duplicate_counts.get(_notification_identity(notification), 0)
        context = (notification, finding, application, repository, retry_job, duplicate_count)
        if notification.status == "queued" and _before(notification.created_at, stale_cutoff):
            items.append(_retry_item("stale_queued_notification", *context, "Queued notification is older than 24 hours"))
        if notification.status == "failed" and retry_job is None:
            items.append(_retry_item("failed_without_retry_job", *context, "Failed notification has no queued retry job"))
        if finding is None:
            items.append(_retry_item("missing_finding_context", *context, "Notification metadata does not resolve to a finding"))
        if duplicate_count > 1:
            items.append(_retry_item("duplicate_notification", *context, "Multiple notifications share channel, subject, finding, and status"))
    return items


def notification_slo_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    sent_by_finding = _sent_notifications_by_finding(db)
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
        .where(models.Finding.severity.in_([models.Severity.critical, models.Severity.high]))
        .order_by(models.Finding.created_at.asc(), models.Finding.id.asc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        deadline = finding.created_at + _slo_window(finding.severity)
        sent_at = sent_by_finding.get(finding.id)
        breached = (sent_at is None and _after(now, deadline)) or (
            sent_at is not None and _after(sent_at, deadline)
        )
        items.append(
            schemas.NotificationSloOut(
                finding_id=finding.id,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                finding_created_at=finding.created_at,
                deadline_at=deadline,
                notified_at=sent_at,
                breached=breached,
                status="notified" if sent_at else "missing_notification",
            ).model_dump(mode="json")
        )
    return items


def notification_digest_readiness_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    sent_by_finding = _sent_notifications_by_finding(db)
    items = []
    finding_stmt = (
        select(models.Finding, models.Application, models.Repository)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Finding.status == models.FindingStatus.open)
        .order_by(models.Finding.created_at.asc(), models.Finding.id.asc())
    )
    for finding, application, repository in db.execute(finding_stmt):
        if finding.severity in {models.Severity.medium, models.Severity.low, models.Severity.info, models.Severity.unknown}:
            items.append(
                _digest_item(
                    "digest_candidate",
                    finding.severity,
                    "pending_digest",
                    "Medium or lower finding eligible for digest notification",
                    finding.created_at,
                    finding=finding,
                    application=application,
                    repository=repository,
                )
            )
        if finding.severity in {models.Severity.critical, models.Severity.high} and finding.id not in sent_by_finding and _after(cutoff, finding.created_at):
            items.append(
                _digest_item(
                    "missing_critical_high_notification",
                    finding.severity,
                    "missing_notification",
                    "Critical or high finding has no sent notification after 24 hours",
                    finding.created_at,
                    finding=finding,
                    application=application,
                    repository=repository,
                )
            )
    for notification in db.scalars(select(models.Notification).where(models.Notification.status == "failed")):
        finding = _finding_from_metadata(db, notification.metadata_json)
        application = db.get(models.Application, finding.application_id) if finding else None
        repository = db.get(models.Repository, application.repository_id) if application else None
        items.append(
            _digest_item(
                "failed_notification",
                notification.severity,
                notification.status,
                notification.subject,
                notification.created_at,
                finding=finding,
                application=application,
                repository=repository,
                notification=notification,
            )
        )
    return items


def _finding_from_metadata(db: Session, metadata: dict | None) -> models.Finding | None:
    if not metadata:
        return None
    finding_id = metadata.get("finding_id")
    if not finding_id:
        return None
    try:
        return db.get(models.Finding, UUID(str(finding_id)))
    except ValueError:
        return None


def _notification_retry_jobs(db: Session) -> list[models.Job]:
    return list(
        db.scalars(
            select(models.Job).where(
                models.Job.job_type == models.JobType.notification,
                models.Job.status.in_([models.JobStatus.queued, models.JobStatus.running]),
            )
        )
    )


def _retry_job_for_notification(notification: models.Notification, jobs: list[models.Job]) -> models.Job | None:
    notification_id = str(notification.id)
    finding_id = str((notification.metadata_json or {}).get("finding_id") or "")
    for job in jobs:
        payload = job.payload or {}
        if str(payload.get("notification_id") or "") == notification_id:
            return job
        if finding_id and str(payload.get("finding_id") or "") == finding_id:
            return job
        if notification.subject and str(payload.get("subject") or "") == notification.subject:
            return job
    return None


def _duplicate_notification_counts(notifications: list[models.Notification]) -> dict[tuple[str, str, str, str], int]:
    counts: dict[tuple[str, str, str, str], int] = {}
    for notification in notifications:
        identity = _notification_identity(notification)
        counts[identity] = counts.get(identity, 0) + 1
    return counts


def _notification_identity(notification: models.Notification) -> tuple[str, str, str, str]:
    return (
        notification.channel,
        notification.subject,
        str((notification.metadata_json or {}).get("finding_id") or ""),
        notification.status,
    )


def _retry_item(
    gap_type: str,
    notification: models.Notification,
    finding: models.Finding | None,
    application: models.Application | None,
    repository: models.Repository | None,
    retry_job: models.Job | None,
    duplicate_count: int,
    detail: str,
) -> dict:
    return schemas.NotificationRetryPostureOut(
        gap_type=gap_type,
        notification_id=notification.id,
        channel=notification.channel,
        severity=notification.severity,
        status=notification.status,
        finding_id=finding.id if finding else None,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        retry_job_id=retry_job.id if retry_job else None,
        duplicate_count=duplicate_count,
        detail=detail,
        created_at=notification.created_at,
    ).model_dump(mode="json")


def _sent_notifications_by_finding(db: Session) -> dict[UUID, datetime]:
    notifications = db.execute(
        select(models.Notification)
        .where(models.Notification.status == "sent")
        .order_by(models.Notification.sent_at.asc().nullslast(), models.Notification.created_at.asc())
    ).scalars()
    by_finding = {}
    for notification in notifications:
        finding_id = _metadata_uuid((notification.metadata_json or {}).get("finding_id"))
        if finding_id and finding_id not in by_finding:
            by_finding[finding_id] = notification.sent_at or notification.created_at
    return by_finding


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _metadata_uuid(value: object) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(str(value))
    except ValueError:
        return None


def _slo_window(severity: models.Severity) -> timedelta:
    if severity == models.Severity.critical:
        return timedelta(hours=1)
    return timedelta(hours=24)


def _digest_item(
    issue_type: str,
    severity: models.Severity,
    status: str,
    detail: str,
    created_at: datetime,
    finding: models.Finding | None = None,
    application: models.Application | None = None,
    repository: models.Repository | None = None,
    notification: models.Notification | None = None,
) -> dict:
    return schemas.NotificationDigestReadinessOut(
        issue_type=issue_type,
        severity=severity,
        finding_id=finding.id if finding else None,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        notification_id=notification.id if notification else None,
        channel=notification.channel if notification else None,
        status=status,
        detail=detail,
        created_at=created_at,
    ).model_dump(mode="json")


def _after(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value > reference
