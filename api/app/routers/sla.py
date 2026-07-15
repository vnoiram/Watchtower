from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/sla", tags=["sla"])

SLA_DAYS = {
    models.Severity.critical: 7,
    models.Severity.high: 14,
    models.Severity.medium: 30,
    models.Severity.low: 90,
    models.Severity.info: 90,
    models.Severity.unknown: 90,
}


@router.get("/findings", response_model=schemas.CursorPage)
def list_sla_findings(
    limit: int = 50,
    breached: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    stmt = (
        select(
            models.Finding,
            models.Application,
            models.Repository,
            models.Vulnerability,
            models.Component,
        )
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .where(models.Finding.status == models.FindingStatus.open)
        .order_by(models.Finding.created_at.asc(), models.Finding.risk_score.desc())
    )

    items = []
    for finding, application, repository, vulnerability, component in db.execute(stmt):
        payload = sla_payload(finding, application, repository, vulnerability, component, now)
        if breached is not None and payload.breached is not breached:
            continue
        items.append(payload.model_dump(mode="json"))
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


def count_sla_breached_findings(db: Session, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    findings = db.execute(
        select(models.Finding).where(models.Finding.status == models.FindingStatus.open)
    ).scalars()
    return sum(1 for finding in findings if is_sla_breached(finding, now))


def is_sla_breached(finding: models.Finding, now: datetime) -> bool:
    due_at = finding.created_at + timedelta(days=SLA_DAYS.get(finding.severity, 90))
    return due_at < _matching_datetime(now, due_at)


def sla_payload(
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    vulnerability: models.Vulnerability,
    component: models.Component,
    now: datetime,
) -> schemas.SlaFindingOut:
    sla_days = SLA_DAYS.get(finding.severity, 90)
    due_at = finding.created_at + timedelta(days=sla_days)
    comparable_now = _matching_datetime(now, finding.created_at)
    age_days = max(0, (comparable_now - finding.created_at).days)
    return schemas.SlaFindingOut(
        finding_id=finding.id,
        severity=finding.severity,
        status=finding.status,
        risk_score=finding.risk_score,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        vulnerability_external_id=vulnerability.external_id,
        component_name=component.name,
        created_at=finding.created_at,
        age_days=age_days,
        sla_days=sla_days,
        due_at=due_at,
        breached=due_at < _matching_datetime(now, due_at),
    )


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
