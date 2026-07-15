from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/sbom-coverage", tags=["sbom-coverage"])


@router.get("", response_model=schemas.CursorPage)
def list_sbom_coverage(
    limit: int = 50,
    missing: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    latest_sboms = _latest_active_source_sboms(db, [application.id for application, _ in rows])
    component_counts = _component_counts(db, [sbom.id for sbom in latest_sboms.values()])

    items = []
    for application, repository in rows:
        sbom = latest_sboms.get(application.id)
        has_active_source_sbom = sbom is not None
        if missing is True and has_active_source_sbom:
            continue
        if missing is False and not has_active_source_sbom:
            continue
        items.append(
            schemas.SbomCoverageOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                has_active_source_sbom=has_active_source_sbom,
                latest_sbom_id=sbom.id if sbom else None,
                latest_sbom_generated_at=sbom.generated_at if sbom else None,
                component_count=component_counts.get(sbom.id, 0) if sbom else 0,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


def _latest_active_source_sboms(
    db: Session,
    application_ids: list[UUID],
) -> dict[UUID, models.Sbom]:
    latest_sboms = {}
    if not application_ids:
        return latest_sboms
    sboms = db.execute(
        select(models.Sbom)
        .where(
            models.Sbom.application_id.in_(application_ids),
            models.Sbom.active.is_(True),
            models.Sbom.sbom_kind == "source",
        )
        .order_by(models.Sbom.application_id.asc(), models.Sbom.generated_at.desc(), models.Sbom.id.desc())
    ).scalars()
    for sbom in sboms:
        latest_sboms.setdefault(sbom.application_id, sbom)
    return latest_sboms


def _component_counts(db: Session, sbom_ids: list[UUID]) -> dict[UUID, int]:
    if not sbom_ids:
        return {}
    rows = db.execute(
        select(models.SbomComponent.sbom_id, func.count(models.SbomComponent.component_id))
        .where(models.SbomComponent.sbom_id.in_(sbom_ids))
        .group_by(models.SbomComponent.sbom_id)
    )
    return {sbom_id: count for sbom_id, count in rows}
