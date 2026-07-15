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
