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


@router.get("/invalidation-candidates", response_model=schemas.CursorPage)
def list_vex_invalidation_candidates(
    limit: int = 50,
    reason: str | None = None,
    expired: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = vex_invalidation_candidate_items(db)
    if reason:
        items = [item for item in items if item["reason"] == reason]
    if expired is not None:
        items = [item for item in items if item["expired"] is expired]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


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


def vex_invalidation_candidate_items(db: Session) -> list[dict]:
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
        .order_by(models.VexStatement.review_date.asc(), models.VexStatement.id.asc())
    )
    items = []
    for vex, finding, application, repository, component, vulnerability in db.execute(stmt):
        expired = vex.review_date < _matching_datetime(now, vex.review_date)
        context = (vex, finding, application, repository, component, vulnerability, expired)
        if expired:
            items.append(_invalidation_item("expired_review", *context, detail="VEX review date has passed"))
        if not vex.approved_by:
            items.append(_invalidation_item("missing_approval", *context, detail="VEX statement has no approver"))
        if finding.last_seen_scan_id and finding.updated_at > _matching_datetime(vex.updated_at, finding.updated_at):
            items.append(_invalidation_item("finding_seen_after_vex", *context, detail="Finding was updated after VEX approval"))
        if component.version and vex.impact_statement and component.version not in vex.impact_statement:
            items.append(_invalidation_item("component_version_drift", *context, detail="Current component version is not reflected in VEX impact statement"))
    return items


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference


def _invalidation_item(
    reason: str,
    vex: models.VexStatement,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    expired: bool,
    detail: str,
) -> dict:
    return schemas.VexInvalidationCandidateOut(
        reason=reason,
        vex_id=vex.id,
        finding_id=finding.id,
        status=vex.status,
        finding_status=finding.status,
        severity=finding.severity,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        component_version=component.version,
        vulnerability_external_id=vulnerability.external_id,
        review_date=vex.review_date,
        expired=expired,
        detail=detail,
    ).model_dump(mode="json")
