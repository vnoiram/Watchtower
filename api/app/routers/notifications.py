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
