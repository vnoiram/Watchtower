from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/audit", tags=["audit"])

PRIVILEGED_ACTIONS = {
    "application.create",
    "backup.restore",
    "backup.restore.verify",
    "job.create",
    "repository.create",
    "repository.scan.enqueue",
    "restore.verify",
    "scan.create",
    "vex.create",
}


@router.get("/review", response_model=schemas.CursorPage)
def list_audit_review(
    limit: int = 50,
    reason: str | None = None,
    actor: str | None = None,
    role: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = audit_review_items(db)
    if reason:
        items = [item for item in items if item["reason"] == reason]
    if actor:
        items = [item for item in items if item["actor"] == actor]
    if role:
        items = [item for item in items if item["role"] == role]
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def audit_review_items(db: Session) -> list[dict]:
    items = []
    stmt = select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())
    for audit_log in db.scalars(stmt):
        review_reason = _audit_review_reason(audit_log)
        if not review_reason:
            continue
        items.append(
            schemas.AuditReviewOut(
                id=audit_log.id,
                actor=audit_log.actor,
                role=audit_log.role,
                action=audit_log.action,
                resource_type=audit_log.resource_type,
                resource_id=audit_log.resource_id,
                reason=review_reason,
                metadata_json=audit_log.metadata_json or {},
                created_at=audit_log.created_at,
            ).model_dump(mode="json")
        )
    return items


def _audit_review_reason(audit_log: models.AuditLog) -> str | None:
    metadata = audit_log.metadata_json or {}
    searchable = f"{audit_log.action} {metadata}".lower()
    if audit_log.role != "admin" and audit_log.action in PRIVILEGED_ACTIONS:
        return "privileged_non_admin"
    if "fail" in searchable or "error" in searchable:
        return "failure_event"
    if audit_log.action in {"scan.create", "job.create", "repository.scan.enqueue"}:
        return "manual_operation"
    if audit_log.action in {"repository.create", "application.create", "vex.create"}:
        return "configuration_change"
    if "manual" in searchable:
        return "manual_operation"
    return None
