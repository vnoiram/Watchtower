from __future__ import annotations

from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.services.github import (
    GitHubAuthError,
    get_repository_installation_token,
    github_api_headers,
    github_app_configured,
)
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
ISSUE_CREATE_STATUSES = {"queued", "pending_provider"}
GITHUB_ISSUES_API = "https://api.github.com/repos/{owner}/{name}/issues"


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


def process_github_issue_actions(
    db: Session,
    *,
    action_ids: list[UUID],
    settings: Settings,
) -> list[RemediationAction]:
    actions = list(select_issue_actions_for_creation(db, action_ids=action_ids))
    processed: list[RemediationAction] = []

    for action in actions:
        if action.provider_id or action.url:
            continue
        if created_github_issue_action_exists(db, finding_id=action.finding_id, exclude_action_id=action.id):
            action.status = "skipped_duplicate"
            set_action_metadata(action, error=None, skipped_reason="github issue already created")
            processed.append(action)
            continue
        payload = build_github_issue_payload(db, action)
        if isinstance(payload, str):
            action.status = "failed"
            set_action_metadata(action, error=payload)
            processed.append(action)
            continue

        repository = payload.pop("_repository")
        token = github_issue_auth_token(repository, settings)
        if isinstance(token, str) and not token:
            action.status = "failed"
            set_action_metadata(action, error="github authentication is not configured")
            processed.append(action)
            continue
        if isinstance(token, GitHubAuthError):
            action.status = "failed"
            set_action_metadata(action, error=str(token))
            processed.append(action)
            continue

        api_url = GITHUB_ISSUES_API.format(owner=repository.owner, name=repository.name)
        try:
            response = httpx.post(
                api_url,
                json=payload,
                headers=github_api_headers(token),
                timeout=10.0,
            )
            if response.status_code < 200 or response.status_code >= 300:
                action.status = "failed"
                set_action_metadata(
                    action,
                    error=f"github issue create failed with status {response.status_code}: {response.text}",
                )
                processed.append(action)
                continue

            response_payload = response.json()
            issue_number = response_payload.get("number")
            html_url = response_payload.get("html_url")
            created_api_url = response_payload.get("url")
            action.status = "created"
            action.provider_id = str(issue_number) if issue_number is not None else None
            action.url = html_url
            metadata = dict(action.metadata_json or {})
            metadata.update(
                {
                    "github_issue_url": html_url,
                    "html_url": html_url,
                    "api_url": created_api_url,
                }
            )
            metadata.pop("error", None)
            action.metadata_json = metadata
            processed.append(action)
        except Exception as exc:  # noqa: BLE001
            action.status = "failed"
            set_action_metadata(action, error=f"github issue create failed: {exc}")
            processed.append(action)

    return processed


def github_issue_auth_token(repository: Repository, settings: Settings) -> str | GitHubAuthError:
    if github_app_configured(settings):
        try:
            return get_repository_installation_token(repository, settings)
        except GitHubAuthError as exc:
            return exc
    if settings.github_token:
        return settings.github_token
    return ""


def select_issue_actions_for_creation(
    db: Session,
    *,
    action_ids: list[UUID],
):
    if action_ids:
        stmt = select(RemediationAction).where(
            RemediationAction.id.in_(action_ids),
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.status.in_(ISSUE_CREATE_STATUSES),
        )
    else:
        stmt = select(RemediationAction).where(
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.status.in_(ISSUE_CREATE_STATUSES),
        )
    return db.scalars(stmt)


def created_github_issue_action_exists(
    db: Session,
    *,
    finding_id: UUID,
    exclude_action_id: UUID,
) -> bool:
    action = db.scalar(
        select(RemediationAction).where(
            RemediationAction.finding_id == finding_id,
            RemediationAction.id != exclude_action_id,
            RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            RemediationAction.status == "created",
        )
    )
    return action is not None


def build_github_issue_payload(
    db: Session,
    action: RemediationAction,
) -> dict[str, object] | str:
    metadata = action.metadata_json or {}
    repository_id = metadata.get("repository_id")
    if not repository_id:
        return "remediation action metadata is missing repository_id"

    try:
        repository_uuid = UUID(str(repository_id))
    except ValueError:
        return f"repository_id is not a valid UUID: {repository_id}"

    repository = db.get(Repository, repository_uuid)
    if not repository:
        return f"repository not found: {repository_id}"
    if repository.provider != RepositoryProvider.github:
        return f"repository provider is not github: {repository.provider.value}"
    if not repository.owner or not repository.name:
        return "github repository owner/name is missing"

    finding = db.get(Finding, action.finding_id)
    if not finding:
        return f"finding not found: {action.finding_id}"
    application = db.get(Application, finding.application_id)
    component = db.get(Component, finding.component_id)
    vulnerability = db.get(Vulnerability, finding.vulnerability_id)
    if not application or not component or not vulnerability:
        return "finding is missing application, component, or vulnerability"

    component_label = component.name or component.purl
    title = (
        f"[Watchtower] {finding.severity.value} vulnerability "
        f"{vulnerability.external_id} in {component_label}"
    )
    fixed_version = action.fixed_version or finding.fixed_version or "not available"
    body = "\n".join(
        [
            f"## {vulnerability.external_id}",
            "",
            f"- Application: {application.name}",
            f"- Component: {component.name}",
            f"- Package URL: {component.purl}",
            f"- Vulnerability: {vulnerability.external_id}",
            f"- Severity: {finding.severity.value}",
            f"- Fixed version: {fixed_version}",
            f"- Risk score: {finding.risk_score:.1f}",
            f"- Finding ID: {finding.id}",
            f"- Remediation action ID: {action.id}",
        ]
    )
    return {"title": title, "body": body, "_repository": repository}


def set_action_metadata(
    action: RemediationAction,
    *,
    error: str | None,
    skipped_reason: str | None = None,
) -> None:
    metadata = dict(action.metadata_json or {})
    if error is None:
        metadata.pop("error", None)
    else:
        metadata["error"] = error
    if skipped_reason:
        metadata["skipped_reason"] = skipped_reason
    action.metadata_json = metadata
