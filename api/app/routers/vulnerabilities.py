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
