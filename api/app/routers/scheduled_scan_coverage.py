from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.scan_health import _latest_scans_by_application

router = APIRouter(prefix="/scheduled-scan-coverage", tags=["scheduled-scan-coverage"])


@router.get("", response_model=schemas.CursorPage)
def list_scheduled_scan_coverage(
    limit: int = 50,
    missing: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scheduled_scan_coverage_items(db)
    if missing is not None:
        items = [item for item in items if item["missing_recent_schedule"] is missing]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def missing_scheduled_scan_count(db: Session) -> int:
    return sum(1 for item in scheduled_scan_coverage_items(db) if item["missing_recent_schedule"])


def scheduled_scan_coverage_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    application_ids = [application.id for application, _ in rows]
    latest_scans = _latest_scans_by_application(db, application_ids)
    latest_scheduled_scans = _latest_scheduled_scans_by_application(db, application_ids)
    items = []
    for application, repository in rows:
        latest_scan = latest_scans.get(application.id)
        scheduled_scan = latest_scheduled_scans.get(application.id)
        missing_recent = scheduled_scan is None or scheduled_scan.created_at < _matching_datetime(
            cutoff,
            scheduled_scan.created_at,
        )
        manual_only = latest_scan is not None and latest_scan.trigger_type == models.TriggerType.manual
        items.append(
            schemas.ScheduledScanCoverageOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                latest_scheduled_scan_id=scheduled_scan.id if scheduled_scan else None,
                latest_scheduled_scan_status=scheduled_scan.status if scheduled_scan else None,
                latest_scheduled_scan_created_at=scheduled_scan.created_at if scheduled_scan else None,
                latest_scan_id=latest_scan.id if latest_scan else None,
                latest_scan_status=latest_scan.status if latest_scan else None,
                latest_scan_trigger_type=latest_scan.trigger_type if latest_scan else None,
                manual_only=manual_only,
                missing_recent_schedule=missing_recent,
            ).model_dump(mode="json")
        )
    return items


def _latest_scheduled_scans_by_application(db: Session, application_ids: list) -> dict:
    if not application_ids:
        return {}
    scans = db.execute(
        select(models.Scan)
        .where(
            models.Scan.application_id.in_(application_ids),
            models.Scan.trigger_type == models.TriggerType.schedule,
        )
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    ).scalars()
    by_application = {}
    for scan in scans:
        by_application.setdefault(scan.application_id, scan)
    return by_application


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
