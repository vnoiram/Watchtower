from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


@router.get("", response_model=schemas.CursorPage)
def list_vulnerabilities(
    limit: int = 50,
    external_id: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    open_findings = func.count(distinct(models.Finding.id)).label("open_finding_count")
    affected_apps = func.count(distinct(models.Finding.application_id)).label("affected_application_count")
    stmt = (
        select(models.Vulnerability, open_findings, affected_apps)
        .outerjoin(
            models.Finding,
            (models.Vulnerability.id == models.Finding.vulnerability_id)
            & (models.Finding.status == models.FindingStatus.open),
        )
        .group_by(models.Vulnerability.id)
    )
    if external_id:
        stmt = stmt.where(models.Vulnerability.external_id.ilike(f"%{external_id}%"))
    if severity:
        stmt = stmt.where(models.Vulnerability.severity == severity)
    stmt = stmt.order_by(open_findings.desc(), models.Vulnerability.external_id.asc()).limit(min(limit, 100))

    items = []
    for vulnerability, open_finding_count, affected_application_count in db.execute(stmt):
        items.append(
            schemas.VulnerabilityInventoryOut(
                id=vulnerability.id,
                source=vulnerability.source,
                external_id=vulnerability.external_id,
                title=vulnerability.title,
                severity=vulnerability.severity,
                cvss_score=vulnerability.cvss_score,
                open_finding_count=open_finding_count,
                affected_application_count=affected_application_count,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/impact", response_model=schemas.CursorPage)
def list_vulnerability_impact(
    limit: int = 50,
    external_id: str | None = None,
    severity: models.Severity | None = None,
    status: models.FindingStatus | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
    )
    if external_id:
        stmt = stmt.where(models.Vulnerability.external_id.ilike(f"%{external_id}%"))
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if status:
        stmt = stmt.where(models.Finding.status == status)
    if application_id:
        stmt = stmt.where(models.Application.id == application_id)
    stmt = stmt.order_by(
        models.Finding.risk_score.desc(),
        models.Vulnerability.external_id.asc(),
        models.Application.name.asc(),
        models.Finding.id.asc(),
    ).limit(min(limit, 100))
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        items.append(
            schemas.VulnerabilityImpactOut(
                finding_id=finding.id,
                finding_status=finding.status,
                severity=finding.severity,
                risk_score=finding.risk_score,
                fixed_version=finding.fixed_version,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_id=component.id,
                component_name=component.name,
                component_version=component.version,
                vulnerability_id=vulnerability.id,
                vulnerability_external_id=vulnerability.external_id,
                vulnerability_title=vulnerability.title,
                last_seen_scan_id=finding.last_seen_scan_id,
                updated_at=finding.updated_at,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/reevaluation-coverage", response_model=schemas.CursorPage)
def list_vulnerability_reevaluation_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    severity: models.Severity | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = vulnerability_reevaluation_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if application_id:
        items = [item for item in items if item["application_id"] == str(application_id)]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/enrichment-coverage", response_model=schemas.CursorPage)
def list_vulnerability_enrichment_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    severity: models.Severity | None = None,
    source: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = vulnerability_enrichment_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if source:
        items = [item for item in items if item["source"] == source]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/source-provenance", response_model=schemas.CursorPage)
def list_vulnerability_source_provenance(
    limit: int = 50,
    gap_type: str | None = None,
    source: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = vulnerability_source_provenance_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if source:
        items = [item for item in items if item["source"] == source]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def vulnerability_reevaluation_gap_count(db: Session) -> int:
    return len(vulnerability_reevaluation_coverage_items(db))


def vulnerability_enrichment_gap_count(db: Session) -> int:
    return len(vulnerability_enrichment_coverage_items(db))


def vulnerability_provenance_gap_count(db: Session) -> int:
    return len(vulnerability_source_provenance_items(db))


def vulnerability_source_provenance_items(db: Session) -> list[dict]:
    affected_counts = {
        vulnerability_id: count
        for vulnerability_id, count in db.execute(
            select(models.Finding.vulnerability_id, func.count(models.Finding.id)).group_by(
                models.Finding.vulnerability_id
            )
        )
    }
    latest_scan_by_vulnerability = _latest_scan_by_vulnerability(db)
    items = []
    for vulnerability in db.scalars(select(models.Vulnerability).order_by(models.Vulnerability.severity.asc(), models.Vulnerability.external_id.asc())):
        evidence = _vulnerability_evidence_text(vulnerability)
        common = (vulnerability, int(affected_counts.get(vulnerability.id, 0)), _has_token(evidence, {"raw", "storage", "artifact", "object"}))
        if not vulnerability.references:
            items.append(_source_provenance_item("missing_reference", *common, "Vulnerability has no reference URLs"))
        if not vulnerability.published_at:
            items.append(_source_provenance_item("missing_published_at", *common, "Vulnerability has no published timestamp"))
        if not vulnerability.modified_at:
            items.append(_source_provenance_item("missing_modified_at", *common, "Vulnerability has no modified timestamp"))
        if not common[2]:
            items.append(_source_provenance_item("missing_raw_data_location", *common, "Vulnerability has no raw source storage evidence"))
        latest_scan = latest_scan_by_vulnerability.get(vulnerability.id)
        if vulnerability.modified_at and latest_scan and vulnerability.modified_at > _matching_datetime(latest_scan.created_at, vulnerability.modified_at):
            items.append(_source_provenance_item("stale_reevaluation", *common, "Vulnerability was modified after latest related scan"))
    return items


def vulnerability_enrichment_coverage_items(db: Session) -> list[dict]:
    affected_counts = {
        vulnerability_id: count
        for vulnerability_id, count in db.execute(
            select(models.Finding.vulnerability_id, func.count(models.Finding.id)).group_by(
                models.Finding.vulnerability_id
            )
        )
    }
    affected_context = _first_finding_context_by_vulnerability(db)
    stmt = select(models.Vulnerability).order_by(models.Vulnerability.severity.asc(), models.Vulnerability.external_id.asc())
    items = []
    for vulnerability in db.scalars(stmt):
        evidence = _vulnerability_evidence_text(vulnerability)
        context = affected_context.get(vulnerability.id)
        common = (vulnerability, int(affected_counts.get(vulnerability.id, 0)), context)
        if vulnerability.cvss_score is None:
            items.append(_enrichment_item("missing_cvss", *common, "Vulnerability has no CVSS score"))
        if not _has_token(evidence, {"epss"}):
            items.append(_enrichment_item("missing_epss", *common, "Vulnerability has no EPSS evidence"))
        if not _has_token(evidence, {"kev", "cisa"}):
            items.append(_enrichment_item("missing_kev", *common, "Vulnerability has no CISA KEV evidence"))
        if not _has_token(evidence, {"exploit", "poc", "proof-of-concept"}):
            items.append(_enrichment_item("missing_exploit_availability", *common, "Vulnerability has no exploit availability evidence"))
        if not _has_token(evidence, {"raw", "storage", "artifact", "object"}):
            items.append(_enrichment_item("missing_raw_data_location", *common, "Vulnerability has no raw data storage evidence"))
        if not vulnerability.references:
            items.append(_enrichment_item("missing_references", *common, "Vulnerability has no reference URLs"))
    return items


def _source_provenance_item(
    gap_type: str,
    vulnerability: models.Vulnerability,
    affected_count: int,
    has_raw_data_location: bool,
    detail: str,
) -> dict:
    return schemas.VulnerabilitySourceProvenanceOut(
        gap_type=gap_type,
        vulnerability_id=vulnerability.id,
        source=vulnerability.source,
        external_id=vulnerability.external_id,
        severity=vulnerability.severity,
        reference_count=len(vulnerability.references or []),
        affected_finding_count=affected_count,
        has_raw_data_location=has_raw_data_location,
        published_at=vulnerability.published_at,
        modified_at=vulnerability.modified_at,
        detail=detail,
    ).model_dump(mode="json")


def _latest_scan_by_vulnerability(db: Session) -> dict[UUID, models.Scan]:
    stmt = (
        select(models.Finding, models.Scan)
        .join(models.Scan, models.Finding.last_seen_scan_id == models.Scan.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
    )
    latest = {}
    for finding, scan in db.execute(stmt):
        latest.setdefault(finding.vulnerability_id, scan)
    return latest


def vulnerability_reevaluation_coverage_items(db: Session) -> list[dict]:
    stale_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status.in_([models.FindingStatus.open, models.FindingStatus.triaged, models.FindingStatus.in_progress]))
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    )
    rows = list(db.execute(stmt))
    application_ids = [application.id for _, application, _, _, _ in rows]
    latest_scans = _latest_scans_by_application(db, application_ids)
    scan_ids = {finding.last_seen_scan_id for finding, _, _, _, _ in rows if finding.last_seen_scan_id is not None}
    last_seen_scans = {scan.id: scan for scan in db.scalars(select(models.Scan).where(models.Scan.id.in_(scan_ids)))} if scan_ids else {}
    items = []
    for finding, application, repository, component, vulnerability in rows:
        latest_scan = latest_scans.get(application.id)
        last_seen_scan = last_seen_scans.get(finding.last_seen_scan_id)
        context = (finding, application, repository, component, vulnerability, latest_scan, last_seen_scan)
        if latest_scan is None:
            items.append(_reevaluation_item("missing_scan_evidence", *context, "Finding has no application scan evidence"))
            continue
        if finding.last_seen_scan_id is None:
            items.append(_reevaluation_item("missing_last_seen_scan", *context, "Finding has no last-seen scan evidence"))
        elif latest_scan.id != finding.last_seen_scan_id:
            items.append(_reevaluation_item("stale_last_seen_scan", *context, "Finding was not observed in the latest scan"))
        if vulnerability.modified_at and last_seen_scan and vulnerability.modified_at > last_seen_scan.created_at:
            items.append(_reevaluation_item("vulnerability_updated_after_scan", *context, "Vulnerability metadata changed after last finding scan"))
        if latest_scan.created_at < _matching_datetime(stale_cutoff, latest_scan.created_at):
            items.append(_reevaluation_item("stale_vulnerability_scan", *context, "Latest scan is older than 30 days"))
    return items


def _first_finding_context_by_vulnerability(
    db: Session,
) -> dict[UUID, tuple[models.Finding, models.Application, models.Repository]]:
    stmt = (
        select(models.Finding, models.Application, models.Repository)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc(), models.Finding.id.asc())
    )
    contexts = {}
    for finding, application, repository in db.execute(stmt):
        contexts.setdefault(finding.vulnerability_id, (finding, application, repository))
    return contexts


def _vulnerability_evidence_text(vulnerability: models.Vulnerability) -> str:
    values = [
        vulnerability.title,
        vulnerability.description,
        vulnerability.references or [],
        vulnerability.source,
        vulnerability.external_id,
    ]
    return _flatten_text(values)


def _flatten_text(value) -> str:
    if isinstance(value, dict):
        return " ".join([str(key).lower() for key in value] + [_flatten_text(item) for item in value.values()])
    if isinstance(value, list | tuple | set):
        return " ".join(_flatten_text(item) for item in value)
    return str(value or "").lower()


def _has_token(text: str, tokens: set[str]) -> bool:
    return any(token in text for token in tokens)


def _enrichment_item(
    gap_type: str,
    vulnerability: models.Vulnerability,
    affected_count: int,
    context: tuple[models.Finding, models.Application, models.Repository] | None,
    detail: str,
) -> dict:
    evidence = _vulnerability_evidence_text(vulnerability)
    finding = context[0] if context else None
    application = context[1] if context else None
    repository = context[2] if context else None
    return schemas.VulnerabilityEnrichmentCoverageOut(
        gap_type=gap_type,
        vulnerability_id=vulnerability.id,
        source=vulnerability.source,
        external_id=vulnerability.external_id,
        severity=vulnerability.severity,
        cvss_score=vulnerability.cvss_score,
        reference_count=len(vulnerability.references or []),
        affected_finding_count=affected_count,
        has_epss=_has_token(evidence, {"epss"}),
        has_kev=_has_token(evidence, {"kev", "cisa"}),
        has_exploit=_has_token(evidence, {"exploit", "poc", "proof-of-concept"}),
        has_raw_data_location=_has_token(evidence, {"raw", "storage", "artifact", "object"}),
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        repository_id=repository.id if repository else None,
        repository_owner=repository.owner if repository else None,
        repository_name=repository.name if repository else None,
        detail=detail if finding is None else f"{detail}: representative finding {finding.id}",
    ).model_dump(mode="json")


def _latest_scans_by_application(db: Session, application_ids: list[UUID]) -> dict[UUID, models.Scan]:
    if not application_ids:
        return {}
    scans = db.scalars(
        select(models.Scan)
        .where(models.Scan.application_id.in_(application_ids))
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    )
    by_application = {}
    for scan in scans:
        by_application.setdefault(scan.application_id, scan)
    return by_application


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference


def _reevaluation_item(
    gap_type: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    latest_scan: models.Scan | None,
    last_seen_scan: models.Scan | None,
    detail: str,
) -> dict:
    return schemas.VulnerabilityReevaluationCoverageOut(
        gap_type=gap_type,
        finding_id=finding.id,
        status=finding.status,
        severity=finding.severity,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        component_version=component.version,
        vulnerability_id=vulnerability.id,
        vulnerability_external_id=vulnerability.external_id,
        vulnerability_modified_at=vulnerability.modified_at,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        last_seen_scan_id=finding.last_seen_scan_id,
        last_seen_scan_created_at=last_seen_scan.created_at if last_seen_scan else None,
        detail=detail,
        updated_at=finding.updated_at,
    ).model_dump(mode="json")
