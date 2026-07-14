from sqlalchemy.orm import Session

from api.app.models import AuditLog


def audit(db: Session, actor: str, role: str, action: str, resource_type: str, resource_id: str | None = None, **metadata) -> None:
    db.add(
        AuditLog(
            actor=actor,
            role=role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata_json=metadata,
        )
    )

