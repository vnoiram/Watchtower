from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/storage", tags=["storage"])


@router.get("/cleanup-candidates", response_model=schemas.CursorPage)
def list_storage_cleanup_candidates(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    items = []
    items.extend(_inactive_sboms(db))
    items.extend(_old_scan_artifacts(db, cutoff))
    items.extend(_failed_scans_without_sbom(db))
    items.sort(key=lambda item: item["created_at"], reverse=True)
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/retention", response_model=list[schemas.RetentionReviewOut])
def retention_review(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return retention_review_items(db)


@router.get("/pressure", response_model=list[schemas.StoragePressureOut])
def storage_pressure(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return storage_pressure_items(db)


def retention_review_count(db: Session) -> int:
    return sum(item.count for item in retention_review_items(db))


def storage_pressure_count(db: Session) -> int:
    return sum(item.count for item in storage_pressure_items(db) if item.status != "ok")


def retention_review_items(db: Session) -> list[schemas.RetentionReviewOut]:
    cutoff_90 = datetime.now(timezone.utc) - timedelta(days=90)
    old_scan_artifacts = len(_old_scan_artifacts(db, cutoff_90))
    inactive_sboms = db.scalar(
        select(func.count()).select_from(models.Sbom).where(models.Sbom.active.is_(False))
    ) or 0
    old_audit_logs = sum(1 for log in db.scalars(select(models.AuditLog)) if _before(log.created_at, cutoff_90))
    cleanup_candidates = len(list_storage_cleanup_candidates(db=db, _=None).items)
    return [
        _retention_item("old_scan_artifacts", old_scan_artifacts, "Scan artifacts older than 90 days"),
        _retention_item("inactive_sboms", inactive_sboms, "Inactive SBOM records eligible for review"),
        _retention_item("old_audit_logs", old_audit_logs, "Audit logs older than 90 days"),
        _retention_item("cleanup_candidates", cleanup_candidates, "Storage cleanup candidates awaiting review"),
    ]


def storage_pressure_items(db: Session) -> list[schemas.StoragePressureOut]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    missing_storage_keys = _count(
        db,
        select(models.Sbom).where((models.Sbom.storage_key.is_(None)) | (models.Sbom.storage_key == "")),
    )
    inactive_sboms = db.scalar(
        select(func.count()).select_from(models.Sbom).where(models.Sbom.active.is_(False))
    ) or 0
    old_artifacts = _old_scan_artifacts(db, cutoff)
    failed_without_sbom = _failed_scans_without_sbom(db)
    artifact_count = 0
    estimated_bytes = 0
    for scan in db.scalars(select(models.Scan)):
        for artifact in _artifacts(scan.result_summary):
            artifact_count += 1
            estimated_bytes += _artifact_size(artifact)
    cleanup = len(list_storage_cleanup_candidates(db=db, _=None).items)
    return [
        _pressure("missing_storage_keys", "fail", missing_storage_keys, 0, "SBOM records without storage_key"),
        _pressure("inactive_sboms", "warn", inactive_sboms, 0, "Inactive SBOM records"),
        _pressure("old_scan_artifacts", "warn", len(old_artifacts), _cleanup_estimated_bytes(old_artifacts), "Scan artifacts older than 90 days"),
        _pressure("failed_scan_without_sbom", "warn", len(failed_without_sbom), 0, "Failed scans that did not store SBOM output"),
        _pressure("artifact_inventory", "ok", artifact_count, estimated_bytes, "Stored artifact records found in scan summaries"),
        _pressure("cleanup_backlog", "warn", cleanup, _cleanup_estimated_bytes(old_artifacts), "Storage cleanup candidates awaiting review"),
    ]


def _inactive_sboms(db: Session) -> list[dict]:
    stmt = (
        select(models.Sbom, models.Application, models.Repository)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Sbom.active.is_(False))
        .order_by(models.Sbom.generated_at.desc(), models.Sbom.id.asc())
    )
    return [
        _cleanup_item(
            reason="inactive_sbom",
            storage_key=sbom.storage_key,
            digest=sbom.sbom_digest,
            scan_id=sbom.scan_id,
            sbom_id=sbom.id,
            application=application,
            repository=repository,
            created_at=sbom.generated_at,
        )
        for sbom, application, repository in db.execute(stmt)
    ]


def _old_scan_artifacts(db: Session, cutoff: datetime) -> list[dict]:
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        if not _before(scan.created_at, cutoff):
            continue
        for artifact in _artifacts(scan.result_summary):
            storage_key = artifact.get("storage_key")
            if not storage_key:
                continue
            items.append(
                _cleanup_item(
                    reason="old_scan_artifact",
                    storage_key=storage_key,
                    digest=artifact.get("digest"),
                    scan_id=scan.id,
                    sbom_id=None,
                    application=application,
                    repository=repository,
                    created_at=scan.created_at,
                )
            )
    return items


def _failed_scans_without_sbom(db: Session) -> list[dict]:
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Scan.status == models.ScanStatus.failed)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        if (scan.result_summary or {}).get("sbom_stored") is not False:
            continue
        items.append(
            _cleanup_item(
                reason="failed_scan_without_sbom",
                storage_key=None,
                digest=None,
                scan_id=scan.id,
                sbom_id=None,
                application=application,
                repository=repository,
                created_at=scan.created_at,
            )
        )
    return items


def _cleanup_item(
    *,
    reason: str,
    storage_key: str | None,
    digest: str | None,
    scan_id,
    sbom_id,
    application: models.Application,
    repository: models.Repository,
    created_at: datetime,
) -> dict:
    return schemas.StorageCleanupCandidateOut(
        reason=reason,
        storage_key=storage_key,
        digest=digest,
        scan_id=scan_id,
        sbom_id=sbom_id,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        created_at=created_at,
    ).model_dump(mode="json")


def _artifacts(result_summary: dict[str, Any] | None) -> list[dict[str, Any]]:
    raw = (result_summary or {}).get("artifacts", {})
    if isinstance(raw, dict):
        return [value for value in raw.values() if isinstance(value, dict)]
    if isinstance(raw, list):
        return [value for value in raw if isinstance(value, dict)]
    return []


def _artifact_size(artifact: dict[str, Any]) -> int:
    for key in ("size_bytes", "bytes", "size"):
        value = artifact.get(key)
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _count(db: Session, stmt) -> int:
    subquery = stmt.subquery()
    return db.scalar(select(func.count()).select_from(subquery)) or 0


def _cleanup_estimated_bytes(items: list[dict]) -> int:
    return sum(int(item.get("estimated_bytes") or 0) for item in items)


def _pressure(check: str, nonzero_status: str, count: int, estimated_bytes: int, detail: str) -> schemas.StoragePressureOut:
    return schemas.StoragePressureOut(
        check=check,
        status=nonzero_status if count else "ok",
        count=count,
        estimated_bytes=estimated_bytes,
        detail=detail,
    )


def _before(value: datetime, cutoff: datetime) -> bool:
    if value.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=None)
    return value < cutoff


def _retention_item(item: str, count: int, detail: str) -> schemas.RetentionReviewOut:
    return schemas.RetentionReviewOut(
        item=item,
        status="warn" if count else "ok",
        count=count,
        detail=detail,
    )
