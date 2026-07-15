from typing import Any
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


@router.get("/usage", response_model=schemas.CursorPage)
def list_component_usage(
    limit: int = 50,
    name: str | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Component, models.Sbom, models.Application, models.Repository)
        .join(models.SbomComponent, models.Component.id == models.SbomComponent.component_id)
        .join(models.Sbom, models.SbomComponent.sbom_id == models.Sbom.id)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Sbom.active.is_(True))
    )
    if name:
        stmt = stmt.where(models.Component.name.ilike(f"%{name}%"))
    if purl:
        stmt = stmt.where(models.Component.purl.ilike(f"%{purl}%"))
    if ecosystem:
        stmt = stmt.where(models.Component.ecosystem == ecosystem)
    if application_id:
        stmt = stmt.where(models.Application.id == application_id)
    stmt = stmt.order_by(
        models.Component.name.asc(),
        models.Component.version.asc().nullslast(),
        models.Application.name.asc(),
        models.Sbom.generated_at.desc(),
    )
    items = []
    seen: set[tuple[UUID, UUID]] = set()
    for component, sbom, application, repository in db.execute(stmt):
        key = (component.id, application.id)
        if key in seen:
            continue
        seen.add(key)
        items.append(
            schemas.ComponentUsageOut(
                component_id=component.id,
                purl=component.purl,
                ecosystem=component.ecosystem,
                component_name=component.name,
                component_version=component.version,
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                active_sbom_id=sbom.id,
                generated_at=sbom.generated_at,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
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


@router.get("/licenses", response_model=schemas.CursorPage)
def list_license_review(
    limit: int = 50,
    issue_type: str | None = None,
    ecosystem: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.Component).order_by(models.Component.name.asc(), models.Component.id.asc())
    if ecosystem:
        stmt = stmt.where(models.Component.ecosystem == ecosystem)
    components = list(db.scalars(stmt))
    usage_by_component = _component_usage_by_id(db, [component.id for component in components])
    items = []
    for component in components:
        current_issue = _license_issue(component.license)
        if not current_issue:
            continue
        if issue_type and current_issue != issue_type:
            continue
        usages = usage_by_component.get(component.id) or [None]
        for usage in usages:
            items.append(
                schemas.LicenseReviewOut(
                    issue_type=current_issue,
                    component_id=component.id,
                    purl=component.purl,
                    ecosystem=component.ecosystem,
                    component_name=component.name,
                    component_version=component.version,
                    license=component.license,
                    application_id=usage.application_id if usage else None,
                    application_name=usage.application_name if usage else None,
                    repository_id=usage.repository_id if usage else None,
                    repository_owner=usage.repository_owner if usage else None,
                    repository_name=usage.repository_name if usage else None,
                ).model_dump(mode="json")
            )
            if len(items) >= min(limit, 100):
                return schemas.CursorPage(items=items, next_cursor=None)
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/dependency-relationships", response_model=schemas.CursorPage)
def list_dependency_relationships(
    limit: int = 50,
    gap_type: str | None = None,
    ecosystem: str | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = dependency_relationship_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if ecosystem:
        items = [item for item in items if item["ecosystem"] == ecosystem]
    if application_id:
        items = [item for item in items if item["application_id"] == str(application_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def dependency_relationship_gap_count(db: Session) -> int:
    return len(dependency_relationship_items(db))


def dependency_relationship_items(db: Session) -> list[dict]:
    stmt = (
        select(models.Component, models.Sbom, models.Application, models.Repository, models.Scan)
        .join(models.SbomComponent, models.Component.id == models.SbomComponent.component_id)
        .join(models.Sbom, models.SbomComponent.sbom_id == models.Sbom.id)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .outerjoin(models.Scan, models.Sbom.scan_id == models.Scan.id)
        .where(models.Sbom.active.is_(True))
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc(), models.Component.name.asc())
    )
    items = []
    for component, sbom, application, repository, scan in db.execute(stmt):
        metadata = _dependency_metadata(component, scan.result_summary if scan else None)
        context = (component, sbom, application, repository, metadata)
        if _metadata_value(metadata, "direct", "direct_dependency", "is_direct") is None:
            items.append(_dependency_relationship_item("missing_direct_dependency", *context, "Direct/transitive dependency evidence is missing"))
        if _metadata_value(metadata, "scope", "dependency_scope") is None:
            items.append(_dependency_relationship_item("missing_dependency_scope", *context, "Dependency scope evidence is missing"))
        if _metadata_value(metadata, "path", "dependency_path") is None:
            items.append(_dependency_relationship_item("missing_dependency_path", *context, "Dependency path evidence is missing"))
        if _metadata_value(metadata, "development", "development_dependency", "dev") is None:
            items.append(_dependency_relationship_item("missing_development_flag", *context, "Development dependency flag is missing"))
        if _metadata_value(metadata, "optional", "optional_dependency") is None:
            items.append(_dependency_relationship_item("missing_optional_flag", *context, "Optional dependency flag is missing"))
    return items


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


def _license_issue(license_value: str | None) -> str | None:
    if not license_value:
        return "missing_license"
    normalized = license_value.lower()
    if normalized in {"unknown", "unknown license", "noassertion"}:
        return "unknown_license"
    if any(token in normalized for token in ["agpl", "lgpl", "gpl"]):
        return "copyleft_license"
    return None


def _dependency_metadata(component: models.Component, result_summary: dict[str, Any] | None) -> dict[str, Any]:
    candidates = _dependency_candidates(result_summary or {})
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        values = _flatten_text(candidate)
        if component.purl and component.purl.lower() in values:
            return candidate
        if component.name and component.name.lower() in values:
            return candidate
    return {}


def _dependency_candidates(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        items: list[dict[str, Any]] = []
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"dependencies", "dependency_relationships", "dependency_graph", "components"}:
                if isinstance(child, list):
                    items.extend(item for item in child if isinstance(item, dict))
                elif isinstance(child, dict):
                    items.extend(item for item in child.values() if isinstance(item, dict))
            items.extend(_dependency_candidates(child))
        return items
    if isinstance(value, list):
        items = []
        for child in value:
            items.extend(_dependency_candidates(child))
        return items
    return []


def _metadata_value(metadata: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def _metadata_bool(metadata: dict[str, Any], *keys: str) -> bool | None:
    value = _metadata_value(metadata, *keys)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "y", "direct", "dev", "optional"}
    return bool(value)


def _flatten_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join([str(key).lower() for key in value] + [_flatten_text(item) for item in value.values()])
    if isinstance(value, list | tuple | set):
        return " ".join(_flatten_text(item) for item in value)
    return str(value or "").lower()


def _dependency_relationship_item(
    gap_type: str,
    component: models.Component,
    sbom: models.Sbom,
    application: models.Application,
    repository: models.Repository,
    metadata: dict[str, Any],
    detail: str,
) -> dict:
    return schemas.DependencyRelationshipOut(
        gap_type=gap_type,
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
        active_sbom_id=sbom.id,
        direct_dependency=_metadata_bool(metadata, "direct", "direct_dependency", "is_direct"),
        dependency_scope=_metadata_value(metadata, "scope", "dependency_scope"),
        dependency_path=_metadata_value(metadata, "path", "dependency_path"),
        development_dependency=_metadata_bool(metadata, "development", "development_dependency", "dev"),
        optional_dependency=_metadata_bool(metadata, "optional", "optional_dependency"),
        detail=detail,
    ).model_dump(mode="json")
