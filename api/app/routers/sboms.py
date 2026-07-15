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


@router.get("/normalization-quality", response_model=schemas.CursorPage)
def list_sbom_normalization_quality(
    limit: int = 50,
    gap_type: str | None = None,
    ecosystem: str | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = sbom_normalization_quality_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if ecosystem:
        items = [item for item in items if item["ecosystem"] == ecosystem]
    if application_id:
        items = [item for item in items if item["application_id"] == str(application_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def sbom_normalization_quality_count(db: Session) -> int:
    return len(sbom_normalization_quality_items(db))


def sbom_normalization_quality_items(db: Session) -> list[dict]:
    duplicate_keys = _duplicate_component_keys(db)
    stmt = (
        select(models.Sbom, models.Component, models.Application, models.Repository)
        .join(models.SbomComponent, models.Sbom.id == models.SbomComponent.sbom_id)
        .join(models.Component, models.SbomComponent.component_id == models.Component.id)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Sbom.active.is_(True))
        .order_by(models.Sbom.generated_at.desc(), models.Component.name.asc(), models.Component.id.asc())
    )
    items = []
    for sbom, component, application, repository in db.execute(stmt):
        context = (sbom, component, application, repository)
        if not component.purl or not component.purl.startswith("pkg:"):
            items.append(_normalization_item("invalid_purl", *context, "Component has no valid package URL"))
        if not component.ecosystem:
            items.append(_normalization_item("missing_ecosystem", *context, "Component has no ecosystem"))
        if not component.name:
            items.append(_normalization_item("missing_name", *context, "Component has no normalized name"))
        if not component.version:
            items.append(_normalization_item("missing_version", *context, "Component has no version"))
        if not component.license:
            items.append(_normalization_item("missing_license", *context, "Component has no license evidence"))
        if not component.supplier:
            items.append(_normalization_item("missing_supplier", *context, "Component has no supplier evidence"))
        if not component.hash:
            items.append(_normalization_item("missing_hash", *context, "Component has no hash evidence"))
        if _component_key(component) in duplicate_keys:
            items.append(_normalization_item("duplicate_identity", *context, "Multiple components share ecosystem, name, and version"))
    return items


def _duplicate_component_keys(db: Session) -> set[tuple[str | None, str, str | None]]:
    rows = db.execute(
        select(models.Component.ecosystem, models.Component.name, models.Component.version)
        .group_by(models.Component.ecosystem, models.Component.name, models.Component.version)
        .having(func.count(models.Component.id) > 1)
    )
    return {(ecosystem, name, version) for ecosystem, name, version in rows}


def _component_key(component: models.Component) -> tuple[str | None, str, str | None]:
    return (component.ecosystem, component.name, component.version)


def _normalization_item(
    gap_type: str,
    sbom: models.Sbom,
    component: models.Component,
    application: models.Application,
    repository: models.Repository,
    detail: str,
) -> dict:
    return schemas.SbomNormalizationQualityOut(
        gap_type=gap_type,
        sbom_id=sbom.id,
        component_id=component.id,
        purl=component.purl,
        ecosystem=component.ecosystem,
        component_name=component.name,
        component_version=component.version,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        generated_at=sbom.generated_at,
    ).model_dump(mode="json")
