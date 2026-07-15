from datetime import datetime, timedelta, timezone
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


@router.get("/resolution-candidates", response_model=schemas.CursorPage)
def list_resolution_candidates(
    limit: int = 50,
    severity: models.Severity | None = None,
    status: models.FindingStatus | None = None,
    application_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    statuses = [
        models.FindingStatus.open,
        models.FindingStatus.triaged,
        models.FindingStatus.in_progress,
    ]
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
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    )
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if status:
        stmt = stmt.where(models.Finding.status == status)
    if application_id:
        stmt = stmt.where(models.Finding.application_id == application_id)
    latest_successful_scans = _latest_successful_scans_by_application(db)
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        latest_scan = latest_successful_scans.get(application.id)
        if latest_scan is None or finding.last_seen_scan_id == latest_scan.id:
            continue
        items.append(
            schemas.FindingResolutionCandidateOut(
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
                last_seen_scan_id=finding.last_seen_scan_id,
                latest_successful_scan_id=latest_scan.id,
                latest_successful_scan_created_at=latest_scan.created_at,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/lifecycle-review", response_model=schemas.CursorPage)
def list_finding_lifecycle_review(
    limit: int = 50,
    issue_type: str | None = None,
    severity: models.Severity | None = None,
    status: models.FindingStatus | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = finding_lifecycle_review_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if status:
        items = [item for item in items if item["status"] == status.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


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


def finding_lifecycle_review_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=30)
    issue_actions = _issue_actions_by_finding(db)
    items = []
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .order_by(models.Finding.updated_at.asc(), models.Finding.id.asc())
    )
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        context = (finding, application, repository, component, vulnerability, now)
        if finding.status in {models.FindingStatus.open, models.FindingStatus.triaged, models.FindingStatus.in_progress} and _before(finding.updated_at, stale_cutoff):
            items.append(_lifecycle_item("stale_open", *context, detail="Open finding has not been updated in 30 days"))
        if finding.status in {models.FindingStatus.accepted_risk, models.FindingStatus.false_positive}:
            items.append(_lifecycle_item(f"{finding.status.value}_review", *context, detail="Exception-like finding status requires periodic review"))
        if finding.status == models.FindingStatus.resolved and _close_state(issue_actions.get(finding.id)) != "closed":
            items.append(_lifecycle_item("resolved_without_close", *context, detail="Resolved finding does not have closed GitHub issue evidence"))
    return items


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


def _latest_successful_scans_by_application(db: Session) -> dict:
    scans = db.execute(
        select(models.Scan)
        .where(models.Scan.status == models.ScanStatus.succeeded)
        .order_by(models.Scan.application_id.asc(), models.Scan.created_at.desc(), models.Scan.id.desc())
    ).scalars()
    by_application = {}
    for scan in scans:
        by_application.setdefault(scan.application_id, scan)
    return by_application


def _issue_actions_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    actions = {}
    stmt = (
        select(models.RemediationAction)
        .where(
            models.RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            models.RemediationAction.provider == "github",
        )
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.desc())
    )
    for action in db.scalars(stmt):
        actions.setdefault(action.finding_id, action)
    return actions


def _close_state(action: models.RemediationAction | None) -> str:
    if action is None:
        return "not_requested"
    if action.status == "closed":
        return "closed"
    if action.status == "close_failed":
        return "close_failed"
    return "pending_close"


def _lifecycle_item(
    issue_type: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    now: datetime,
    detail: str,
) -> dict:
    updated_at = finding.updated_at
    age_days = max((now.replace(tzinfo=None) - updated_at.replace(tzinfo=None)).days, 0)
    return schemas.FindingLifecycleReviewOut(
        issue_type=issue_type,
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
        age_days=age_days,
        updated_at=finding.updated_at,
        detail=detail,
    ).model_dump(mode="json")


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
