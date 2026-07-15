from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/remediation-actions", tags=["remediation-actions"])


@router.get("", response_model=schemas.CursorPage)
def list_remediation_actions(
    limit: int = 50,
    status: str | None = None,
    action_type: str | None = None,
    finding_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(
            models.RemediationAction,
            models.Finding,
            models.Application,
            models.Vulnerability,
            models.Component,
        )
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
    )
    if status:
        stmt = stmt.where(models.RemediationAction.status == status)
    if action_type:
        stmt = stmt.where(models.RemediationAction.action_type == action_type)
    if finding_id:
        stmt = stmt.where(models.RemediationAction.finding_id == finding_id)
    stmt = stmt.order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc()).limit(min(limit, 100))

    items = []
    for action, finding, application, vulnerability, component in db.execute(stmt):
        items.append(
            schemas.RemediationActionOut(
                id=action.id,
                finding_id=action.finding_id,
                action_type=action.action_type,
                status=action.status,
                provider=action.provider,
                provider_id=action.provider_id,
                url=action.url,
                branch=action.branch,
                fixed_version=action.fixed_version,
                metadata_json=action.metadata_json,
                created_at=action.created_at,
                updated_at=action.updated_at,
                finding_severity=finding.severity,
                finding_status=finding.status,
                application_id=application.id,
                application_name=application.name,
                vulnerability_external_id=vulnerability.external_id,
                component_name=component.name,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)
