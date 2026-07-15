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


def _sboms_by_scan(db: Session) -> dict[UUID, models.Sbom]:
    sboms = db.execute(
        select(models.Sbom).order_by(models.Sbom.generated_at.desc(), models.Sbom.id.desc())
    ).scalars()
    by_scan = {}
    for sbom in sboms:
        by_scan.setdefault(sbom.scan_id, sbom)
    return by_scan
