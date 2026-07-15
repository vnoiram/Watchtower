from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


@router.get("", response_model=schemas.CursorPage)
def list_audit_logs(
    limit: int = 50,
    actor: str | None = None,
    role: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.AuditLog)
    if actor:
        stmt = stmt.where(models.AuditLog.actor == actor)
    if role:
        stmt = stmt.where(models.AuditLog.role == role)
    if action:
        stmt = stmt.where(models.AuditLog.action == action)
    if resource_type:
        stmt = stmt.where(models.AuditLog.resource_type == resource_type)
    stmt = stmt.order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc()).limit(
        min(limit, 100)
    )
    items = [
        schemas.AuditLogOut(
            id=row.id,
            actor=row.actor,
            role=row.role,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            metadata_json=row.metadata_json,
            created_at=row.created_at,
        ).model_dump(mode="json")
        for row in db.execute(stmt).scalars()
    ]
    return schemas.CursorPage(items=items, next_cursor=None)
