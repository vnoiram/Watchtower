from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("", response_model=schemas.CursorPage)
def list_artifacts(
    limit: int = 50,
    artifact_type: str | None = None,
    application_id: UUID | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    if application_id:
        stmt = stmt.where(models.Application.id == application_id)
    if repository_id:
        stmt = stmt.where(models.Repository.id == repository_id)

    sboms_by_scan = _sboms_by_scan(db)
    items = []
    for scan, application, repository in db.execute(stmt):
        artifacts = (scan.result_summary or {}).get("artifacts") or {}
        if not isinstance(artifacts, dict):
            continue
        for current_type, payload in artifacts.items():
            if artifact_type and current_type != artifact_type:
                continue
            if not isinstance(payload, dict) or not payload.get("storage_key"):
                continue
            sbom = sboms_by_scan.get(scan.id) if current_type == "source_sbom" else None
            items.append(
                schemas.ArtifactInventoryOut(
                    scan_id=scan.id,
                    scan_status=scan.status,
                    scan_created_at=scan.created_at,
                    application_id=application.id,
                    application_name=application.name,
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                    artifact_type=current_type,
                    storage_key=str(payload["storage_key"]),
                    digest=payload.get("digest"),
                    sbom_id=sbom.id if sbom else None,
                    sbom_kind=sbom.sbom_kind if sbom else None,
                ).model_dump(mode="json")
            )
            if len(items) >= min(limit, 100):
                return schemas.CursorPage(items=items, next_cursor=None)
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/sbom-coverage", response_model=schemas.CursorPage)
def list_artifact_sbom_coverage(
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
    artifact_sboms = _artifact_sboms_by_application(db)
    artifact_types = _artifact_types_by_application(db)
    items = []
    for application, repository in rows:
        sbom = artifact_sboms.get(application.id)
        types = artifact_types.get(application.id, [])
        has_artifact_sbom = sbom is not None or bool(types)
        if missing is not None and has_artifact_sbom is not (not missing):
            continue
        items.append(
            schemas.ArtifactSbomCoverageOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                has_artifact_sbom=has_artifact_sbom,
                latest_artifact_sbom_id=sbom.id if sbom else None,
                latest_artifact_sbom_generated_at=sbom.generated_at if sbom else None,
                artifact_types=types,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/container-coverage", response_model=schemas.CursorPage)
def list_container_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = container_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def container_coverage_count(db: Session) -> int:
    return len(container_coverage_items(db))


def container_coverage_items(db: Session) -> list[dict]:
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    latest_scans = _latest_scan_by_application(db)
    artifact_types = _container_artifact_types_by_application(db)
    container_sboms = _container_sboms_by_application(db)
    items = []
    for application, repository in rows:
        scan = latest_scans.get(application.id)
        types = artifact_types.get(application.id, [])
        has_container_signal = (
            application.application_type == models.ApplicationType.container
            or bool(types)
            or bool(container_sboms.get(application.id))
            or _scan_is_container(scan)
        )
        if not has_container_signal:
            continue
        has_container_artifact = bool(types)
        has_container_sbom = bool(container_sboms.get(application.id)) or "container_sbom" in types
        if not has_container_artifact:
            items.append(
                _container_coverage_item(
                    "missing_container_artifact",
                    application,
                    repository,
                    scan,
                    has_container_artifact,
                    has_container_sbom,
                    types,
                    "Application has no stored container artifact evidence",
                )
            )
        if not has_container_sbom:
            items.append(
                _container_coverage_item(
                    "missing_container_sbom",
                    application,
                    repository,
                    scan,
                    has_container_artifact,
                    has_container_sbom,
                    types,
                    "Application has no container SBOM evidence",
                )
            )
        if scan and _scan_is_container(scan) and scan.status in {
            models.ScanStatus.failed,
            models.ScanStatus.cancelled,
            models.ScanStatus.timed_out,
            models.ScanStatus.partially_succeeded,
        }:
            items.append(
                _container_coverage_item(
                    "failed_container_scan",
                    application,
                    repository,
                    scan,
                    has_container_artifact,
                    has_container_sbom,
                    types,
                    scan.error_message or "Latest container scan did not fully succeed",
                )
            )
    return items


def _sboms_by_scan(db: Session) -> dict[UUID, models.Sbom]:
    sboms = db.execute(
        select(models.Sbom).order_by(models.Sbom.generated_at.desc(), models.Sbom.id.desc())
    ).scalars()
    by_scan = {}
    for sbom in sboms:
        by_scan.setdefault(sbom.scan_id, sbom)
    return by_scan


def _latest_scan_by_application(db: Session) -> dict[UUID, models.Scan]:
    latest = {}
    for scan in db.scalars(select(models.Scan).order_by(models.Scan.created_at.desc(), models.Scan.id.desc())):
        latest.setdefault(scan.application_id, scan)
    return latest


def _container_sboms_by_application(db: Session) -> dict[UUID, models.Sbom]:
    sboms = db.scalars(
        select(models.Sbom)
        .where(models.Sbom.sbom_kind == "container")
        .order_by(models.Sbom.application_id.asc(), models.Sbom.generated_at.desc(), models.Sbom.id.desc())
    )
    by_application = {}
    for sbom in sboms:
        by_application.setdefault(sbom.application_id, sbom)
    return by_application


def _container_artifact_types_by_application(db: Session) -> dict[UUID, list[str]]:
    by_application: dict[UUID, list[str]] = {}
    for scan in db.scalars(select(models.Scan)):
        artifacts = (scan.result_summary or {}).get("artifacts") or {}
        if not isinstance(artifacts, dict):
            continue
        for artifact_type, payload in artifacts.items():
            if not _artifact_type_is_container(str(artifact_type)):
                continue
            if not isinstance(payload, dict) or not payload.get("storage_key"):
                continue
            by_application.setdefault(scan.application_id, [])
            if artifact_type not in by_application[scan.application_id]:
                by_application[scan.application_id].append(str(artifact_type))
    return by_application


def _artifact_type_is_container(artifact_type: str) -> bool:
    text = artifact_type.lower()
    return any(token in text for token in ["container", "image", "trivy"])


def _scan_is_container(scan: models.Scan | None) -> bool:
    if not scan:
        return False
    text = " ".join(str(value) for value in [scan.scan_type, scan.tool, (scan.result_summary or {}).get("scanner")])
    return _artifact_type_is_container(text)


def _container_coverage_item(
    gap_type: str,
    application: models.Application,
    repository: models.Repository,
    scan: models.Scan | None,
    has_container_artifact: bool,
    has_container_sbom: bool,
    artifact_types: list[str],
    detail: str,
) -> dict:
    return schemas.ContainerCoverageOut(
        gap_type=gap_type,
        application_id=application.id,
        application_name=application.name,
        application_type=application.application_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        latest_scan_id=scan.id if scan else None,
        latest_scan_status=scan.status if scan else None,
        latest_scan_created_at=scan.created_at if scan else None,
        has_container_artifact=has_container_artifact,
        has_container_sbom=has_container_sbom,
        artifact_types=artifact_types,
        detail=detail,
    ).model_dump(mode="json")


def _artifact_sboms_by_application(db: Session) -> dict[UUID, models.Sbom]:
    sboms = db.scalars(
        select(models.Sbom)
        .where(models.Sbom.sbom_kind != "source")
        .order_by(models.Sbom.application_id.asc(), models.Sbom.generated_at.desc(), models.Sbom.id.desc())
    )
    by_application = {}
    for sbom in sboms:
        by_application.setdefault(sbom.application_id, sbom)
    return by_application


def _artifact_types_by_application(db: Session) -> dict[UUID, list[str]]:
    rows = db.execute(select(models.Scan))
    by_application: dict[UUID, list[str]] = {}
    for scan in rows.scalars():
        artifacts = (scan.result_summary or {}).get("artifacts") or {}
        if not isinstance(artifacts, dict):
            continue
        for artifact_type, payload in artifacts.items():
            if artifact_type not in {"artifact_sbom", "container_sbom"}:
                continue
            if not isinstance(payload, dict) or not payload.get("storage_key"):
                continue
            by_application.setdefault(scan.application_id, [])
            if artifact_type not in by_application[scan.application_id]:
                by_application[scan.application_id].append(artifact_type)
    return by_application
