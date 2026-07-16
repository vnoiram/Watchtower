from datetime import datetime, timedelta, timezone

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


@router.get("/database-freshness", response_model=schemas.CursorPage)
def list_scanner_database_freshness(
    limit: int = 50,
    gap_type: str | None = None,
    tool: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scanner_database_freshness_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if tool:
        items = [item for item in items if item["tool"] == tool]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/execution-matrix", response_model=schemas.CursorPage)
def list_scanner_execution_matrix(
    limit: int = 50,
    gap_type: str | None = None,
    tool: str | None = None,
    repository_id: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scanner_execution_matrix_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if tool:
        items = [item for item in items if item["tool"] == tool]
    if repository_id:
        items = [item for item in items if item["repository_id"] == repository_id]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/tool-coverage", response_model=schemas.CursorPage)
def list_scanner_tool_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    tool: str | None = None,
    application_id: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scanner_tool_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if tool:
        items = [item for item in items if item["tool"] == tool]
    if application_id:
        items = [item for item in items if item["application_id"] == application_id]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def scanner_database_freshness_count(db: Session) -> int:
    return len(scanner_database_freshness_items(db))


def scanner_execution_gap_count(db: Session) -> int:
    return len(scanner_execution_matrix_items(db))


def scanner_tool_coverage_gap_count(db: Session) -> int:
    return len(scanner_tool_coverage_items(db))


def scanner_execution_matrix_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(models.Application.lifecycle != models.Lifecycle.archived)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )
    scans_by_app = _scans_by_application(db)
    items = []
    for application, repository in rows:
        for tool in _required_tools(application):
            scan = _latest_tool_scan(scans_by_app.get(application.id, []), tool)
            if scan is None:
                items.append(_execution_item("missing_required_scanner", tool, application, repository, None, "Required scanner has no scan record"))
                continue
            if _before(scan.created_at, cutoff):
                items.append(_execution_item("stale_scanner_run", tool, application, repository, scan, "Latest scanner run is older than 30 days"))
            if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out, models.ScanStatus.cancelled}:
                items.append(_execution_item("failed_latest_scanner", tool, application, repository, scan, "Latest scanner run did not complete successfully"))
            if not scan.tool_version:
                items.append(_execution_item("missing_tool_version", tool, application, repository, scan, "Latest scanner run has no tool version"))
    return items


def scanner_tool_coverage_items(db: Session) -> list[dict]:
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(models.Application.lifecycle != models.Lifecycle.archived)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )
    scans_by_app = _scans_by_application(db)
    items = []
    for application, repository in rows:
        scans = scans_by_app.get(application.id, [])
        for tool in _mvp_scanner_tools():
            scan = _latest_tool_scan(scans, tool)
            if scan is None:
                items.append(_tool_coverage_item("missing_tool", tool, application, repository, None, "Required MVP scanner has no scan evidence"))
                continue
            if scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out, models.ScanStatus.cancelled, models.ScanStatus.partially_succeeded}:
                items.append(_tool_coverage_item("unhealthy_latest_scan", tool, application, repository, scan, "Latest required scanner run did not fully succeed"))
    return items


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


def scanner_database_freshness_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=30)
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        if not _scanner_uses_database(scan):
            continue
        db_updated_at = _scanner_database_updated_at(scan)
        failures = [failure for failure in _scan_failures(scan) if failure["failure_type"] == "trivy_db_update" or "db" in (failure["error"] or "").lower()]
        if db_updated_at is None:
            items.append(_database_freshness_item("missing_db_metadata", scan, application, repository, None, None, "Scanner database update timestamp is missing"))
        elif _before(db_updated_at, cutoff):
            items.append(_database_freshness_item("stale_db", scan, application, repository, db_updated_at, _age_days(db_updated_at, now), "Scanner database metadata is older than 30 days"))
        for failure in failures:
            items.append(_database_freshness_item("db_update_failed", scan, application, repository, db_updated_at, _age_days(db_updated_at, now) if db_updated_at else None, failure["error"] or "Scanner database update failed"))
    return items


def _scans_by_application(db: Session) -> dict:
    scans: dict = {}
    for scan in db.scalars(select(models.Scan).order_by(models.Scan.created_at.desc(), models.Scan.id.desc())):
        scans.setdefault(scan.application_id, []).append(scan)
    return scans


def _required_tools(application: models.Application) -> list[str]:
    tools = ["osv", "trivy", "grype", "gitleaks", "semgrep"]
    if application.application_type == models.ApplicationType.container:
        tools.append("container")
    return tools


def _mvp_scanner_tools() -> list[str]:
    return ["osv", "trivy", "syft"]


def _latest_tool_scan(scans: list[models.Scan], tool: str) -> models.Scan | None:
    return next((scan for scan in scans if _tool_matches(scan, tool)), None)


def _tool_matches(scan: models.Scan, tool: str) -> bool:
    text = " ".join(str(value or "").lower() for value in [scan.tool, scan.scan_type, scan.result_summary])
    if tool == "container":
        return "container" in text or "image" in text
    return tool in text


def _execution_item(
    gap_type: str,
    tool: str,
    application: models.Application,
    repository: models.Repository,
    scan: models.Scan | None,
    detail: str,
) -> dict:
    return schemas.ScannerExecutionMatrixOut(
        gap_type=gap_type,
        tool=tool,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        latest_scan_id=scan.id if scan else None,
        latest_scan_status=scan.status if scan else None,
        latest_scan_created_at=scan.created_at if scan else None,
        tool_version=scan.tool_version if scan else None,
        detail=detail,
    ).model_dump(mode="json")


def _tool_coverage_item(
    gap_type: str,
    tool: str,
    application: models.Application,
    repository: models.Repository,
    scan: models.Scan | None,
    detail: str,
) -> dict:
    return schemas.ScannerToolCoverageOut(
        gap_type=gap_type,
        tool=tool,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        latest_scan_id=scan.id if scan else None,
        latest_scan_status=scan.status if scan else None,
        latest_scan_created_at=scan.created_at if scan else None,
        detail=detail,
    ).model_dump(mode="json")


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


def _scanner_uses_database(scan: models.Scan) -> bool:
    text = " ".join(str(value) for value in [scan.tool, scan.scan_type, (scan.result_summary or {}).get("scanner")]).lower()
    return any(token in text for token in ["trivy", "osv", "grype", "vulnerability"])


def _scanner_database_updated_at(scan: models.Scan) -> datetime | None:
    summary = scan.result_summary or {}
    candidates = [
        summary.get("database_updated_at"),
        summary.get("db_updated_at"),
        summary.get("vulnerability_db_updated_at"),
    ]
    metadata = summary.get("metadata") or {}
    if isinstance(metadata, dict):
        candidates.extend(
            [
                metadata.get("database_updated_at"),
                metadata.get("db_updated_at"),
                metadata.get("vulnerability_db_updated_at"),
            ]
        )
    for candidate in candidates:
        parsed = _parse_datetime(candidate)
        if parsed:
            return parsed
    return None


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _database_freshness_item(
    gap_type: str,
    scan: models.Scan,
    application: models.Application,
    repository: models.Repository,
    database_updated_at: datetime | None,
    database_age_days: int | None,
    detail: str,
) -> dict:
    return schemas.ScannerDatabaseFreshnessOut(
        gap_type=gap_type,
        scan_id=scan.id,
        tool=scan.tool,
        status=scan.status,
        database_updated_at=database_updated_at,
        database_age_days=database_age_days,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        created_at=scan.created_at,
    ).model_dump(mode="json")


def _age_days(value: datetime, now: datetime) -> int:
    if value.tzinfo is None:
        now = now.replace(tzinfo=None)
    elif now.tzinfo is None:
        value = value.replace(tzinfo=None)
    return max(int((now - value).total_seconds() // 86400), 0)


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _failure_type(tool: object, error: str) -> str:
    text = f"{tool or ''} {error}".lower()
    if "trivy" in text and "db" in text:
        return "trivy_db_update"
    if "timeout" in text or "timed out" in text:
        return "timeout"
    if "auth" in text or "permission" in text or "credential" in text:
        return "auth"
    return "scanner_failure"
