from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import (
    Application,
    Component,
    Finding,
    FindingStatus,
    RemediationAction,
    Repository,
    RepositoryProvider,
    Severity,
    Vulnerability,
)

ACTION_TYPE_GITHUB_ISSUE = "github_issue"
OPEN_REMEDIATION_STATUSES = {"queued", "pending_provider", "created", "in_progress"}
ISSUE_ELIGIBLE_SEVERITIES = {Severity.critical, Severity.high}


def enqueue_github_issue_requests(
    db: Session,
    *,
    finding_ids: list[UUID],
) -> list[RemediationAction]:
    if not finding_ids:
        return []

    created: list[RemediationAction] = []
    for finding_id in finding_ids:
        finding = db.get(Finding, finding_id)
        if not should_create_github_issue(db, finding):
            continue
        if github_issue_action_exists(db, finding_id=finding.id):
            continue

        application = db.get(Application, finding.application_id)
        component = db.get(Component, finding.component_id)
        vulnerability = db.get(Vulnerability, finding.vulnerability_id)
        if not application or not component or not vulnerability:
            continue

        action = RemediationAction(
            finding_id=finding.id,
            action_type=ACTION_TYPE_GITHUB_ISSUE,
            status="queued",
            provider="github",
            fixed_version=finding.fixed_version,
            metadata_json={
                "finding_id": str(finding.id),
                "application_id": str(finding.application_id),
                "repository_id": str(application.repository_id),
                "severity": finding.severity.value,
                "vulnerability_id": str(finding.vulnerability_id),
                "component_id": str(finding.component_id),
                "vulnerability_external_id": vulnerability.external_id,
                "component_purl": component.purl,
            },
        )
        db.add(action)
        db.flush()
        created.append(action)
    return created


def should_create_github_issue(db: Session, finding: Finding | None) -> bool:
    if not finding:
        return False
    if finding.status != FindingStatus.open:
        return False
    if finding.severity not in ISSUE_ELIGIBLE_SEVERITIES:
        return False
    if not finding.fixed_version:
        return False

    application = db.get(Application, finding.application_id)
    if not application:
        return False
    repository = db.get(Repository, application.repository_id)
    return bool(repository and repository.provider == RepositoryProvider.github)


def github_issue_action_exists(db: Session, *, finding_id: UUID) -> bool:
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.finding_id == finding_id,
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.provider == "github",
            RemediationAction.status.in_(OPEN_REMEDIATION_STATUSES),
        )
    )
    return action is not None


def mark_issue_actions_pending_provider(
    db: Session,
    *,
    action_ids: list[UUID],
) -> list[RemediationAction]:
    if action_ids:
        stmt = select(RemediationAction).where(
            RemediationAction.id.in_(action_ids),
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.status == "queued",
        )
    else:
        stmt = select(RemediationAction).where(
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.status == "queued",
        )

    updated: list[RemediationAction] = []
    for action in db.scalars(stmt):
        metadata = dict(action.metadata_json or {})
        metadata["dry_run"] = True
        metadata["reason"] = "github issue delivery is not implemented yet"
        action.metadata_json = metadata
        action.status = "pending_provider"
        updated.append(action)
    return updated
