from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/scanner-versions", tags=["scanner-versions"])


@router.get("", response_model=schemas.CursorPage)
def list_scanner_versions(
    limit: int = 50,
    tool: str | None = None,
    missing_version: bool | None = None,
    stale: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scanner_version_items(db)
    if tool:
        items = [item for item in items if item["tool"] == tool]
    if missing_version is not None:
        items = [item for item in items if item["missing_version"] is missing_version]
    if stale is not None:
        items = [item for item in items if item["stale"] is stale]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def scanner_version_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    groups: dict[tuple[str | None, str | None], list[tuple[models.Scan, models.Application, models.Repository]]] = {}
    rows = db.execute(
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
    )
    for scan, application, repository in rows:
        key = (scan.tool, scan.tool_version)
        groups.setdefault(key, []).append((scan, application, repository))

    items = []
    for (tool, tool_version), scans in groups.items():
        latest_scan, application, repository = max(scans, key=lambda row: (row[0].created_at, str(row[0].id)))
        items.append(
            schemas.ScannerVersionOut(
                tool=tool,
                tool_version=tool_version,
                scan_count=len(scans),
                latest_scan_id=latest_scan.id,
                latest_scan_status=latest_scan.status,
                latest_scan_created_at=latest_scan.created_at,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                missing_version=not bool(tool_version),
                stale=_before(latest_scan.created_at, cutoff),
            ).model_dump(mode="json")
        )
    return sorted(items, key=lambda item: (not item["missing_version"], not item["stale"], item["tool"] or ""))


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
