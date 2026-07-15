from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.services.remediation import ACTION_TYPE_AI_FIX, OPEN_REMEDIATION_STATUSES

router = APIRouter(prefix="/ai-fix", tags=["ai-fix"])


@router.get("", response_model=schemas.CursorPage)
def list_ai_fix_actions(
    limit: int = 50,
    status: str | None = None,
    severity: models.Severity | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = _action_context_stmt().where(models.RemediationAction.action_type == ACTION_TYPE_AI_FIX)
    if status:
        stmt = stmt.where(models.RemediationAction.status == status)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if application_id:
        stmt = stmt.where(models.Application.id == application_id)
    stmt = stmt.order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc()).limit(
        min(limit, 100)
    )

    items = []
    for action, finding, application, vulnerability, component in db.execute(stmt):
        items.append(
            schemas.AiFixActionOut(
                **_action_payload(action, finding, application, vulnerability, component),
                requested_fixed_version=(action.metadata_json or {}).get("fixed_version") or action.fixed_version,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/candidates", response_model=schemas.CursorPage)
def list_ai_fix_candidates(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    open_ai_fix_exists = (
        select(models.RemediationAction.id)
        .where(
            models.RemediationAction.finding_id == models.Finding.id,
            models.RemediationAction.action_type == ACTION_TYPE_AI_FIX,
            models.RemediationAction.status.in_(OPEN_REMEDIATION_STATUSES),
        )
        .exists()
    )
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
        .where(
            models.Finding.status == models.FindingStatus.open,
            models.Finding.fixed_version.is_not(None),
            ~open_ai_fix_exists,
        )
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc())
        .limit(min(limit, 100))
    )

    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        items.append(
            schemas.AiFixCandidateOut(
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
                created_at=finding.created_at,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


def _action_context_stmt():
    return (
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


def _action_payload(
    action: models.RemediationAction,
    finding: models.Finding,
    application: models.Application,
    vulnerability: models.Vulnerability,
    component: models.Component,
) -> dict:
    return schemas.RemediationActionOut(
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
    ).model_dump()
