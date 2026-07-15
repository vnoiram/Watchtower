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


def notification_slo_breach_count(db: Session) -> int:
    return sum(1 for item in notification_slo_items(db) if item["breached"])


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


def _after(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value > reference
