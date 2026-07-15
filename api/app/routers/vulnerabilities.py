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
