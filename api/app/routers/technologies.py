from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/technologies", tags=["technologies"])


@router.get("", response_model=schemas.CursorPage)
def list_technologies(
    limit: int = 50,
    application_id: UUID | None = None,
    category: str | None = None,
    name: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Technology, models.Application, models.Repository)
        .join(models.Application, models.Technology.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
    )
    if application_id:
        stmt = stmt.where(models.Technology.application_id == application_id)
    if category:
        stmt = stmt.where(models.Technology.category == category)
    if name:
        stmt = stmt.where(models.Technology.name.ilike(f"%{name}%"))
    stmt = stmt.order_by(models.Technology.detected_at.desc(), models.Technology.id.asc()).limit(min(limit, 100))

    items = []
    for technology, application, repository in db.execute(stmt):
        items.append(
            schemas.TechnologyInventoryOut(
                id=technology.id,
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                category=technology.category,
                name=technology.name,
                version=technology.version,
                detection_source=technology.detection_source,
                confidence=technology.confidence,
                detected_at=technology.detected_at,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)
