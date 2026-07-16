from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

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


@router.get("/raw-artifacts", response_model=schemas.CursorPage)
def list_raw_scan_artifacts(
    limit: int = 50,
    artifact_type: str | None = None,
    gap_type: str | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = raw_scan_artifact_items(db)
    if artifact_type:
        items = [item for item in items if item["artifact_type"] == artifact_type]
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if repository_id:
        items = [item for item in items if item["repository_id"] == str(repository_id)]
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


@router.get("/format-compliance", response_model=schemas.CursorPage)
def list_scan_format_compliance(
    limit: int = 50,
    gap_type: str | None = None,
    tool: str | None = None,
    status: models.ScanStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scan_format_compliance_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if tool:
        items = [item for item in items if item["tool"] == tool]
    if status:
        items = [item for item in items if item["status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/freshness-buckets", response_model=schemas.CursorPage)
def list_scan_freshness_buckets(
    limit: int = 50,
    bucket: str | None = None,
    lifecycle: models.Lifecycle | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = scan_freshness_bucket_items(db)
    if bucket:
        items = [item for item in items if item["bucket"] == bucket]
    if lifecycle:
        items = [item for item in items if item["lifecycle"] == lifecycle.value]
    if repository_id:
        items = [item for item in items if item["repository_id"] == str(repository_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def daily_scan_slo_breach_count(db: Session) -> int:
    return sum(1 for item in daily_scan_slo_items(db) if item["breached"])


def scan_freshness_gap_count(db: Session) -> int:
    return sum(1 for item in scan_freshness_bucket_items(db) if item["gap"])


def raw_scan_artifact_gap_count(db: Session) -> int:
    return sum(1 for item in raw_scan_artifact_items(db) if item["gap_type"] != "complete")


def scan_format_gap_count(db: Session) -> int:
    return len(scan_format_compliance_items(db))


def scan_format_compliance_items(db: Session) -> list[dict]:
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        if not scan.result_summary:
            items.append(_format_item("missing_result_summary", scan, application, repository, None, "Scan has no result summary"))
        if scan.tool and not scan.tool_version:
            items.append(_format_item("missing_tool_version", scan, application, repository, None, "Scan has tool but no tool version"))
        if _scanner_failures_shape_invalid(scan.result_summary):
            items.append(_format_item("scanner_failure_shape", scan, application, repository, None, "scanner_failures is not a list/dict shape"))
        for artifact_type, artifact in _scan_artifact_payloads(scan.result_summary):
            if not _artifact_format_ok(artifact_type, artifact):
                items.append(
                    _format_item(
                        "unknown_artifact_format",
                        scan,
                        application,
                        repository,
                        artifact_type,
                        "Artifact storage key does not match expected scanner output format",
                    )
                )
    return items


def raw_scan_artifact_items(db: Session) -> list[dict]:
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    items = []
    for scan, application, repository in db.execute(stmt):
        artifacts = _scan_artifact_payloads(scan.result_summary)
        if not artifacts:
            items.append(
                _raw_artifact_item(
                    "missing_raw_artifact",
                    scan,
                    application,
                    repository,
                    None,
                    {},
                    "Scan has no raw artifact metadata",
                )
            )
            continue
        for current_type, artifact in artifacts:
            storage_key = artifact.get("storage_key")
            digest = artifact.get("digest") or artifact.get("sha256")
            encrypted = _artifact_encrypted(artifact)
            gap = "complete"
            detail = "Raw scan artifact has storage and digest evidence"
            if not storage_key:
                gap = "missing_storage_key"
                detail = "Raw scan artifact has no storage key"
            elif not digest:
                gap = "missing_digest"
                detail = "Raw scan artifact has no digest evidence"
            elif not encrypted:
                gap = "missing_encryption_metadata"
                detail = "Raw scan artifact has no encryption metadata"
            items.append(_raw_artifact_item(gap, scan, application, repository, current_type, artifact, detail))
    return items


def _format_item(
    gap_type: str,
    scan: models.Scan,
    application: models.Application,
    repository: models.Repository,
    artifact_type: str | None,
    detail: str,
) -> dict:
    return schemas.ScanFormatComplianceOut(
        gap_type=gap_type,
        scan_id=scan.id,
        status=scan.status,
        tool=scan.tool,
        artifact_type=artifact_type,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        created_at=scan.created_at,
    ).model_dump(mode="json")


def _scanner_failures_shape_invalid(result_summary: dict | None) -> bool:
    if not result_summary or "scanner_failures" not in result_summary:
        return False
    failures = result_summary.get("scanner_failures")
    if isinstance(failures, dict):
        return False
    if isinstance(failures, list):
        return any(not isinstance(item, dict | str) for item in failures)
    return True


def _artifact_format_ok(artifact_type: str | None, artifact: dict) -> bool:
    if not artifact_type:
        return False
    storage_key = str(artifact.get("storage_key") or artifact.get("path") or "").lower()
    declared = str(artifact.get("format") or "").lower()
    text = f"{artifact_type} {storage_key} {declared}".lower()
    if any(token in artifact_type.lower() for token in ["source_sbom", "artifact_sbom", "container_sbom", "sbom"]):
        return "cyclonedx" in text or "cdx" in text or storage_key.endswith(".json")
    if any(token in artifact_type.lower() for token in ["semgrep", "gitleaks", "sarif"]):
        return "sarif" in text or storage_key.endswith(".sarif")
    if any(token in artifact_type.lower() for token in ["osv", "trivy", "grype"]):
        return "json" in text or storage_key.endswith(".json")
    return bool(storage_key)



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


def scan_freshness_bucket_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )
    latest_scans = _latest_scans_by_application(db, [application.id for application, _ in rows])
    items = []
    for application, repository in rows:
        latest_scan = latest_scans.get(application.id)
        bucket, age_days = _freshness_bucket(latest_scan, now)
        gap = application.lifecycle != models.Lifecycle.archived and bucket in {"never", "gt_30d"}
        detail = "Application has no scan record" if latest_scan is None else f"Latest scan is in freshness bucket {bucket}"
        items.append(
            schemas.ScanFreshnessBucketOut(
                bucket=bucket,
                gap=gap,
                application_id=application.id,
                application_name=application.name,
                lifecycle=application.lifecycle,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                latest_scan_id=latest_scan.id if latest_scan else None,
                latest_scan_status=latest_scan.status if latest_scan else None,
                latest_scan_created_at=latest_scan.created_at if latest_scan else None,
                age_days=age_days,
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


def _freshness_bucket(scan: models.Scan | None, now: datetime) -> tuple[str, int | None]:
    if scan is None:
        return "never", None
    comparable_now = _matching_datetime(now, scan.created_at)
    age_days = max((comparable_now - scan.created_at).days, 0)
    if age_days < 1:
        return "lt_24h", age_days
    if age_days <= 7:
        return "1_7d", age_days
    if age_days <= 30:
        return "8_30d", age_days
    return "gt_30d", age_days


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


def _scan_artifact_payloads(result_summary: dict[str, Any] | None) -> list[tuple[str, dict[str, Any]]]:
    raw = (result_summary or {}).get("artifacts") if isinstance(result_summary, dict) else None
    if isinstance(raw, dict):
        return [(str(key), value) for key, value in raw.items() if isinstance(value, dict)]
    if isinstance(raw, list):
        payloads = []
        for index, value in enumerate(raw):
            if isinstance(value, dict):
                payloads.append((str(value.get("type") or value.get("artifact_type") or f"artifact_{index}"), value))
        return payloads
    return []


def _artifact_encrypted(artifact: dict[str, Any]) -> bool:
    if artifact.get("encrypted") or artifact.get("encryption") or artifact.get("kms_key_id"):
        return True
    text = " ".join(str(artifact.get(key) or "").lower() for key in ("storage_key", "digest", "metadata"))
    return "encrypted" in text or "kms" in text


def _artifact_size(artifact: dict[str, Any]) -> int | None:
    for key in ("size_bytes", "bytes", "size"):
        value = artifact.get(key)
        if isinstance(value, int):
            return value
    return None


def _raw_artifact_item(
    gap_type: str,
    scan: models.Scan,
    application: models.Application,
    repository: models.Repository,
    artifact_type: str | None,
    artifact: dict[str, Any],
    detail: str,
) -> dict:
    return schemas.RawScanArtifactOut(
        gap_type=gap_type,
        scan_id=scan.id,
        status=scan.status,
        artifact_type=artifact_type,
        storage_key=artifact.get("storage_key"),
        digest=artifact.get("digest") or artifact.get("sha256"),
        size_bytes=_artifact_size(artifact),
        encrypted=_artifact_encrypted(artifact),
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        created_at=scan.created_at,
    ).model_dump(mode="json")
