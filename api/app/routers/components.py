from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.errors import problem

router = APIRouter(prefix="/components", tags=["components"])


@router.get("", response_model=schemas.CursorPage)
def list_components(
    limit: int = 50,
    name: str | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    active_sboms = func.count(distinct(models.Sbom.id)).label("active_sbom_count")
    applications = func.count(distinct(models.Sbom.application_id)).label("application_count")
    stmt = (
        select(models.Component, active_sboms, applications)
        .outerjoin(models.SbomComponent, models.Component.id == models.SbomComponent.component_id)
        .outerjoin(
            models.Sbom,
            (models.SbomComponent.sbom_id == models.Sbom.id) & (models.Sbom.active.is_(True)),
        )
        .group_by(models.Component.id)
    )
    if name:
        stmt = stmt.where(models.Component.name.ilike(f"%{name}%"))
    if purl:
        stmt = stmt.where(models.Component.purl.ilike(f"%{purl}%"))
    if ecosystem:
        stmt = stmt.where(models.Component.ecosystem == ecosystem)
    stmt = stmt.order_by(applications.desc(), models.Component.name.asc(), models.Component.id.asc()).limit(min(limit, 100))

    rows = list(db.execute(stmt))
    usage_by_component = _component_usage_by_id(db, [component.id for component, _, _ in rows])
    items = []
    for component, active_sbom_count, application_count in rows:
        items.append(_component_out(component, active_sbom_count, application_count, usage_by_component.get(component.id, [])))
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/{component_id}/applications", response_model=list[schemas.ComponentApplicationOut])
def list_component_applications(
    component_id: UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    if not db.get(models.Component, component_id):
        raise problem(404, "Component not found", str(component_id))
    return _component_usage_by_id(db, [component_id]).get(component_id, [])


def _component_out(
    component: models.Component,
    active_sbom_count: int,
    application_count: int,
    applications: list[schemas.ComponentApplicationOut],
) -> dict:
    return schemas.ComponentInventoryOut(
        id=component.id,
        purl=component.purl,
        ecosystem=component.ecosystem,
        namespace=component.namespace,
        name=component.name,
        version=component.version,
        supplier=component.supplier,
        license=component.license,
        active_sbom_count=active_sbom_count,
        application_count=application_count,
        applications=applications,
    ).model_dump(mode="json")


def _component_usage_by_id(
    db: Session,
    component_ids: list[UUID],
) -> dict[UUID, list[schemas.ComponentApplicationOut]]:
    if not component_ids:
        return {}
    stmt = (
        select(models.SbomComponent.component_id, models.Sbom, models.Application, models.Repository)
        .join(models.Sbom, models.SbomComponent.sbom_id == models.Sbom.id)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.SbomComponent.component_id.in_(component_ids), models.Sbom.active.is_(True))
        .order_by(models.Application.name.asc(), models.Sbom.generated_at.desc())
    )
    usage: dict[UUID, list[schemas.ComponentApplicationOut]] = {}
    seen: set[tuple[UUID, UUID]] = set()
    for component_id, sbom, application, repository in db.execute(stmt):
        key = (component_id, application.id)
        if key in seen:
            continue
        seen.add(key)
        usage.setdefault(component_id, []).append(
            schemas.ComponentApplicationOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                active_sbom_id=sbom.id,
                generated_at=sbom.generated_at,
            )
        )
    return usage
