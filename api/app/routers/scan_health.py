from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/scan-health", tags=["scan-health"])


@router.get("", response_model=schemas.CursorPage)
def list_scan_health(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    latest_scans = _latest_scans_by_application(db, [application.id for application, _ in rows])

    items = []
    for application, repository in rows:
        scan = latest_scans.get(application.id)
        stale = scan is None or scan.created_at < _matching_datetime(cutoff, scan.created_at)
        unhealthy = stale or (
            scan is not None
            and scan.status
            in {
                models.ScanStatus.failed,
                models.ScanStatus.partially_succeeded,
            }
        )
        if not unhealthy:
            continue
        items.append(
            schemas.ScanHealthOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                latest_scan_id=scan.id if scan else None,
                latest_scan_status=scan.status if scan else None,
                latest_scan_error_message=scan.error_message if scan else None,
                scanner_failures=_scanner_failures(scan.result_summary if scan else {}),
                latest_scan_created_at=scan.created_at if scan else None,
                latest_scan_completed_at=scan.completed_at if scan else None,
                stale=stale,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


def _latest_scans_by_application(
    db: Session,
    application_ids: list,
) -> dict:
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


def _scanner_failures(result_summary: dict | None) -> list:
    if not result_summary:
        return []
    failures = result_summary.get("scanner_failures", [])
    if isinstance(failures, list):
        return failures
    if isinstance(failures, dict):
        return [failures]
    return [failures]


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
