from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal, require_role
from api.app.errors import problem
from api.app.pagination import apply_cursor, encode_cursor
from api.app.services.remediation import (
    ACTION_TYPE_GITHUB_ISSUE,
    OPEN_REMEDIATION_STATUSES,
    enqueue_github_issue_requests,
    github_issue_action_exists,
    should_create_github_issue,
)

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=schemas.CursorPage)
def list_findings(
    cursor: str | None = None,
    limit: int = 50,
    status: models.FindingStatus | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.Finding)
    if status:
        stmt = stmt.where(models.Finding.status == status)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = apply_cursor(stmt, models.Finding, cursor, limit)
    rows = list(db.execute(stmt).scalars())
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = encode_cursor(last.created_at, last.id)
        rows = rows[:limit]
    return schemas.CursorPage(items=[schemas.FindingOut.model_validate(row).model_dump(mode="json") for row in rows], next_cursor=next_cursor)


@router.post("/{finding_id}/github-issue", response_model=schemas.RemediationActionOut)
def enqueue_github_issue(
    finding_id: UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_role("operator")),
):
    finding = db.get(models.Finding, finding_id)
    if not finding:
        raise problem(404, "Finding not found", str(finding_id))
    existing = _existing_open_github_issue_action(db, finding_id)
    if existing:
        return _remediation_action_out(db, existing)
    if not should_create_github_issue(db, finding):
        raise problem(
            409,
            "Finding is not eligible for GitHub issue queueing",
            "Finding must be open, critical/high, have a fixed version, and belong to a GitHub repository.",
        )

    actions = enqueue_github_issue_requests(db, finding_ids=[finding_id])
    if not actions:
        if github_issue_action_exists(db, finding_id=finding_id):
            existing = _existing_open_github_issue_action(db, finding_id)
            if existing:
                return _remediation_action_out(db, existing)
        raise problem(409, "GitHub issue action was not queued")

    db.commit()
    db.refresh(actions[0])
    return _remediation_action_out(db, actions[0])


def _existing_open_github_issue_action(
    db: Session,
    finding_id: UUID,
) -> models.RemediationAction | None:
    return db.scalar(
        select(models.RemediationAction).where(
            models.RemediationAction.finding_id == finding_id,
            models.RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            models.RemediationAction.provider == "github",
            models.RemediationAction.status.in_(OPEN_REMEDIATION_STATUSES),
        )
    )


def _remediation_action_out(db: Session, action: models.RemediationAction) -> dict:
    finding = db.get(models.Finding, action.finding_id)
    application = db.get(models.Application, finding.application_id) if finding else None
    vulnerability = db.get(models.Vulnerability, finding.vulnerability_id) if finding else None
    component = db.get(models.Component, finding.component_id) if finding else None
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
        finding_severity=finding.severity if finding else None,
        finding_status=finding.status if finding else None,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        vulnerability_external_id=vulnerability.external_id if vulnerability else None,
        component_name=component.name if component else None,
    ).model_dump(mode="json")
