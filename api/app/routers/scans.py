from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.pagination import apply_cursor, encode_cursor
from api.app.services.audit import audit

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=schemas.ScanOut)
def create_scan(
    payload: schemas.ScanCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    scan = models.Scan(**payload.model_dump())
    db.add(scan)
    db.flush()
    audit(db, principal.actor, principal.role, "scan.create", "scan", str(scan.id))
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=schemas.CursorPage)
def list_scans(
    cursor: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = apply_cursor(select(models.Scan), models.Scan, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.ScanOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)


@router.get("/evidence-quality", response_model=schemas.CursorPage)
def list_scan_evidence_quality(
    limit: int = 50,
    gap_type: str | None = None,
    status: models.ScanStatus | None = None,
    tool: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scan_evidence_quality_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if status:
        items = [item for item in items if item["status"] == status.value]
    if tool:
        items = [item for item in items if item["tool"] == tool]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/daily-slo", response_model=schemas.CursorPage)
def list_daily_scan_slo(
    limit: int = 50,
    breached: bool | None = None,
    status: models.ScanStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = daily_scan_slo_items(db)
    if breached is not None:
        items = [item for item in items if item["breached"] is breached]
    if status:
        items = [item for item in items if item["latest_scheduled_scan_status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def daily_scan_slo_breach_count(db: Session) -> int:
    return sum(1 for item in daily_scan_slo_items(db) if item["breached"])


def daily_scan_slo_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(models.Application.lifecycle != models.Lifecycle.archived)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )
    application_ids = [application.id for application, _ in rows]
    latest_scans = _latest_scans_by_application(db, application_ids)
    latest_scheduled_scans = _latest_scheduled_scans_by_application(db, application_ids)
    items = []
    for application, repository in rows:
        latest_scan = latest_scans.get(application.id)
        scheduled_scan = latest_scheduled_scans.get(application.id)
        manual_only = latest_scan is not None and latest_scan.trigger_type == models.TriggerType.manual
        breached = (
            scheduled_scan is None
            or scheduled_scan.status != models.ScanStatus.succeeded
            or scheduled_scan.created_at < _matching_datetime(cutoff, scheduled_scan.created_at)
        )
        if scheduled_scan is None:
            detail = "Application has no scheduled scan record"
        elif scheduled_scan.status != models.ScanStatus.succeeded:
            detail = "Latest scheduled scan did not succeed"
        elif breached:
            detail = "Latest successful scheduled scan is older than 24 hours"
        else:
            detail = "Daily scheduled scan SLO is satisfied"
        items.append(
            schemas.DailyScanSloOut(
                application_id=application.id,
                application_name=application.name,
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
                breached=breached,
                detail=detail,
            ).model_dump(mode="json")
        )
    return items


def scan_evidence_quality_items(db: Session) -> list[dict]:
    sbom_scan_ids = set(db.scalars(select(models.Sbom.scan_id)))
    finding_scan_ids = {
        scan_id
        for scan_id in db.scalars(select(models.Finding.last_seen_scan_id))
        if scan_id is not None
    } | {
        scan_id
        for scan_id in db.scalars(select(models.Finding.first_seen_scan_id))
        if scan_id is not None
    }
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        summary = scan.result_summary or {}
        if not scan.tool:
            items.append(_scan_quality_item("missing_tool", scan, application, repository, "Scan has no tool name evidence"))
        if not scan.tool_version:
            items.append(_scan_quality_item("missing_tool_version", scan, application, repository, "Scan has no tool version evidence"))
        if not scan.commit_sha:
            items.append(_scan_quality_item("missing_commit_sha", scan, application, repository, "Scan has no commit SHA evidence"))
        if not summary:
            items.append(_scan_quality_item("empty_result_summary", scan, application, repository, "Scan result summary is empty"))
        artifacts = summary.get("artifacts") if isinstance(summary, dict) else None
        source_sbom = artifacts.get("source_sbom") if isinstance(artifacts, dict) else None
        if scan.status == models.ScanStatus.succeeded and not (isinstance(source_sbom, dict) and source_sbom.get("storage_key")):
            items.append(_scan_quality_item("missing_source_sbom_artifact", scan, application, repository, "Succeeded scan has no source SBOM artifact evidence"))
        if (summary.get("scanner_failures") if isinstance(summary, dict) else None):
            items.append(_scan_quality_item("scanner_failures", scan, application, repository, "Scan result summary contains scanner failures"))
        if scan.status == models.ScanStatus.succeeded and scan.id not in sbom_scan_ids and scan.id not in finding_scan_ids:
            items.append(_scan_quality_item("empty_successful_scan", scan, application, repository, "Succeeded scan produced no SBOM or finding evidence"))
    return items


def _latest_scans_by_application(db: Session, application_ids: list) -> dict:
    if not application_ids:
        return {}
    scans = db.execute(
        select(models.Scan)
        .where(models.Scan.application_id.in_(application_ids))
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    ).scalars()
    by_application = {}
    for scan in scans:
        by_application.setdefault(scan.application_id, scan)
    return by_application


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


def _scan_quality_item(
    gap_type: str,
    scan: models.Scan,
    application: models.Application,
    repository: models.Repository,
    detail: str,
) -> dict:
    return schemas.ScanEvidenceQualityOut(
        gap_type=gap_type,
        scan_id=scan.id,
        status=scan.status,
        tool=scan.tool,
        tool_version=scan.tool_version,
        commit_sha=scan.commit_sha,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        created_at=scan.created_at,
    ).model_dump(mode="json")
