from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.services.audit import audit

router = APIRouter(prefix="/vex", tags=["vex"])


@router.get("", response_model=schemas.CursorPage)
def list_vex_statements(
    limit: int = 50,
    expired: bool | None = None,
    status: models.VexStatus | None = None,
    finding_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    stmt = (
        select(
            models.VexStatement,
            models.Finding,
            models.Application,
            models.Repository,
            models.Component,
            models.Vulnerability,
        )
        .join(models.Finding, models.VexStatement.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
    )
    if expired is True:
        stmt = stmt.where(models.VexStatement.review_date < now)
    elif expired is False:
        stmt = stmt.where(models.VexStatement.review_date >= now)
    if status:
        stmt = stmt.where(models.VexStatement.status == status)
    if finding_id:
        stmt = stmt.where(models.VexStatement.finding_id == finding_id)
    stmt = stmt.order_by(models.VexStatement.review_date.asc(), models.VexStatement.id.asc()).limit(
        min(limit, 100)
    )

    items = []
    for vex, finding, application, repository, component, vulnerability in db.execute(stmt):
        expired_value = vex.review_date < _matching_datetime(now, vex.review_date)
        items.append(
            schemas.VexInventoryOut(
                id=vex.id,
                finding_id=vex.finding_id,
                status=vex.status,
                justification=vex.justification,
                impact_statement=vex.impact_statement,
                approved_by=vex.approved_by,
                review_date=vex.review_date,
                created_at=vex.created_at,
                updated_at=vex.updated_at,
                finding_status=finding.status,
                finding_severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                component_version=component.version,
                vulnerability_external_id=vulnerability.external_id,
                vulnerability_title=vulnerability.title,
                expired=expired_value,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.post("", response_model=schemas.VexOut)
def create_vex_statement(
    payload: schemas.VexCreate,
    db: Session = Depends(get_db),
    principal: Principal = Depends(require_role("operator")),
):
    vex = models.VexStatement(**payload.model_dump())
    db.add(vex)
    db.flush()
    audit(db, principal.actor, principal.role, "vex.create", "vex", str(vex.id), finding_id=str(vex.finding_id))
    db.commit()
    db.refresh(vex)
    return vex


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference
