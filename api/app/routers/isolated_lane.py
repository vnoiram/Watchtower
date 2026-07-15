from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/isolated-lane", tags=["isolated-lane"])


@router.get("", response_model=schemas.CursorPage)
def list_isolated_lane(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Application, models.Repository)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(_isolated_repository_condition())
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        .limit(min(limit, 100))
    )
    rows = list(db.execute(stmt))
    latest_scans = _latest_scans_by_application(db, [application.id for application, _ in rows])
    sbom_counts = _active_source_sbom_counts(db, [application.id for application, _ in rows])

    items = []
    for application, repository in rows:
        latest_scan = latest_scans.get(application.id)
        items.append(
            schemas.IsolatedLaneOut(
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                repository_provider=repository.provider,
                source_classification=repository.source_classification,
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                latest_scan_id=latest_scan.id if latest_scan else None,
                latest_scan_status=latest_scan.status if latest_scan else None,
                latest_scan_created_at=latest_scan.created_at if latest_scan else None,
                active_source_sbom_count=sbom_counts.get(application.id, 0),
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


def count_isolated_applications(db: Session) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(models.Application)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(_isolated_repository_condition())
        )
        or 0
    )


def _isolated_repository_condition():
    return (models.Repository.provider == models.RepositoryProvider.isolated) | (
        models.Repository.source_classification.in_(
            [models.SourceClassification.restricted, models.SourceClassification.isolated]
        )
    )


def _latest_scans_by_application(
    db: Session,
    application_ids: list[UUID],
) -> dict[UUID, models.Scan]:
    latest_scans = {}
    if not application_ids:
        return latest_scans
    scans = db.execute(
        select(models.Scan)
        .where(models.Scan.application_id.in_(application_ids))
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    ).scalars()
    for scan in scans:
        latest_scans.setdefault(scan.application_id, scan)
    return latest_scans


def _active_source_sbom_counts(db: Session, application_ids: list[UUID]) -> dict[UUID, int]:
    if not application_ids:
        return {}
    rows = db.execute(
        select(models.Sbom.application_id, func.count(models.Sbom.id))
        .where(
            models.Sbom.application_id.in_(application_ids),
            models.Sbom.active.is_(True),
            models.Sbom.sbom_kind == "source",
        )
        .group_by(models.Sbom.application_id)
    )
    return {application_id: count for application_id, count in rows}
