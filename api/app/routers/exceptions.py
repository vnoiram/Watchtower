from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/exceptions", tags=["exceptions"])


@router.get("", response_model=schemas.CursorPage)
def list_exceptions(
    limit: int = 50,
    exception_type: str | None = None,
    severity: models.Severity | None = None,
    expired: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    now = datetime.now(timezone.utc)
    items = []
    if exception_type in {None, models.FindingStatus.accepted_risk.value, models.FindingStatus.false_positive.value}:
        items.extend(_finding_exceptions(db, severity, exception_type, expired))
    if exception_type in {None, "vex"}:
        items.extend(_vex_exceptions(db, severity, expired, now))
    items.sort(key=lambda item: item["review_date"] or item["finding_id"], reverse=True)
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def _finding_exceptions(
    db: Session,
    severity: models.Severity | None,
    exception_type: str | None,
    expired: bool | None,
) -> list[dict]:
    if expired is not None:
        return []
    statuses = [models.FindingStatus.accepted_risk, models.FindingStatus.false_positive]
    stmt = (
        select(
            models.Finding,
            models.Application,
            models.Repository,
            models.Component,
            models.Vulnerability,
        )
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status.in_(statuses))
    )
    if exception_type:
        stmt = stmt.where(models.Finding.status == models.FindingStatus(exception_type))
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = stmt.order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    return [
        schemas.ExceptionReviewOut(
            exception_type=finding.status.value,
            finding_id=finding.id,
            severity=finding.severity,
            status=finding.status,
            application_id=application.id,
            application_name=application.name,
            repository_id=repository.id,
            repository_owner=repository.owner,
            repository_name=repository.name,
            component_name=component.name,
            vulnerability_external_id=vulnerability.external_id,
        ).model_dump(mode="json")
        for finding, application, repository, component, vulnerability in db.execute(stmt)
    ]


def _vex_exceptions(
    db: Session,
    severity: models.Severity | None,
    expired: bool | None,
    now: datetime,
) -> list[dict]:
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
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = stmt.order_by(models.VexStatement.review_date.asc(), models.VexStatement.id.asc())
    items = []
    for vex, finding, application, repository, component, vulnerability in db.execute(stmt):
        is_expired = _before(vex.review_date, now)
        if expired is not None and is_expired is not expired:
            continue
        items.append(
            schemas.ExceptionReviewOut(
                exception_type="vex",
                finding_id=finding.id,
                severity=finding.severity,
                status=vex.status,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                review_date=vex.review_date,
                expired=is_expired,
                justification=vex.justification,
            ).model_dump(mode="json")
        )
    return items


def _before(value: datetime, cutoff: datetime) -> bool:
    if value.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=None)
    return value < cutoff
