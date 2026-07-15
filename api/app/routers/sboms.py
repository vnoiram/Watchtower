from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/sboms", tags=["sboms"])


@router.get("", response_model=schemas.CursorPage)
def list_sboms(
    limit: int = 50,
    active: bool | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    component_count = func.count(models.SbomComponent.component_id).label("component_count")
    stmt = (
        select(models.Sbom, models.Application, models.Repository, component_count)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .outerjoin(models.SbomComponent, models.Sbom.id == models.SbomComponent.sbom_id)
        .group_by(models.Sbom.id, models.Application.id, models.Repository.id)
    )
    if active is not None:
        stmt = stmt.where(models.Sbom.active.is_(active))
    if application_id:
        stmt = stmt.where(models.Sbom.application_id == application_id)
    stmt = stmt.order_by(models.Sbom.generated_at.desc(), models.Sbom.id.asc()).limit(min(limit, 100))

    items = []
    for sbom, application, repository, count in db.execute(stmt):
        items.append(
            schemas.SbomInventoryOut(
                id=sbom.id,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                scan_id=sbom.scan_id,
                sbom_kind=sbom.sbom_kind,
                format=sbom.format,
                specification_version=sbom.specification_version,
                commit_sha=sbom.commit_sha,
                generated_at=sbom.generated_at,
                active=sbom.active,
                component_count=count,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)
