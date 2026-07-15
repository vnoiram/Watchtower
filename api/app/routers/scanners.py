from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/scanners", tags=["scanners"])


@router.get("/failures", response_model=schemas.CursorPage)
def list_scanner_failures(
    limit: int = 50,
    tool: str | None = None,
    status: models.ScanStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scanner_failure_items(db)
    if tool:
        items = [item for item in items if item["tool"] == tool]
    if status:
        items = [item for item in items if item["status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def scanner_failure_items(db: Session) -> list[dict]:
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        for failure in _scan_failures(scan):
            items.append(
                schemas.ScannerFailureOut(
                    scan_id=scan.id,
                    tool=failure["tool"],
                    failure_type=failure["failure_type"],
                    error=failure["error"],
                    status=scan.status,
                    application_id=application.id,
                    application_name=application.name,
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                    created_at=scan.created_at,
                ).model_dump(mode="json")
            )
    return items


def _scan_failures(scan: models.Scan) -> list[dict[str, str | None]]:
    failures = []
    raw_failures = (scan.result_summary or {}).get("scanner_failures") or []
    if isinstance(raw_failures, dict):
        raw_failures = [raw_failures]
    if isinstance(raw_failures, list):
        for raw in raw_failures:
            if isinstance(raw, dict):
                tool = raw.get("tool") or raw.get("scanner") or scan.tool
                error = str(raw.get("error") or raw.get("message") or raw)
            else:
                tool = scan.tool
                error = str(raw)
            failures.append({"tool": str(tool) if tool else None, "failure_type": _failure_type(tool, error), "error": error})
    if scan.error_message and scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out}:
        failures.append(
            {
                "tool": scan.tool,
                "failure_type": _failure_type(scan.tool, scan.error_message),
                "error": scan.error_message,
            }
        )
    return failures


def _failure_type(tool: object, error: str) -> str:
    text = f"{tool or ''} {error}".lower()
    if "trivy" in text and "db" in text:
        return "trivy_db_update"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "auth" in text or "permission" in text or "credential" in text:
        return "auth"
    return "scanner_failure"
