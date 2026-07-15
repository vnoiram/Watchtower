from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/scanner-inventory", tags=["scanner-inventory"])


@router.get("", response_model=schemas.CursorPage)
def list_scanner_inventory(
    limit: int = 50,
    tool: str | None = None,
    status: models.ScanStatus | None = None,
    failed_only: bool = False,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
    )
    if tool:
        stmt = stmt.where(models.Scan.tool == tool)
    if status:
        stmt = stmt.where(models.Scan.status == status)
    stmt = stmt.order_by(models.Scan.created_at.desc(), models.Scan.id.asc())

    items = []
    for scan, application, repository in db.execute(stmt):
        failures = _scanner_failures(scan.result_summary)
        scanner_failure = bool((scan.result_summary or {}).get("scanner_failure") or failures)
        if failed_only and not (scanner_failure or scan.status == models.ScanStatus.failed):
            continue
        items.append(
            schemas.ScannerInventoryOut(
                scan_id=scan.id,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                status=scan.status,
                tool=scan.tool,
                tool_version=scan.tool_version,
                scanner_failure=scanner_failure,
                scanner_failures=failures,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


def _scanner_failures(result_summary: dict | None) -> list:
    if not result_summary:
        return []
    failures = result_summary.get("scanner_failures", [])
    if isinstance(failures, list):
        return failures
    if isinstance(failures, dict):
        return [failures]
    return [failures]
