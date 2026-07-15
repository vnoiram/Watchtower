from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
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


def _before(value: datetime, cutoff: datetime) -> bool:
    if value.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=None)
    return value < cutoff
