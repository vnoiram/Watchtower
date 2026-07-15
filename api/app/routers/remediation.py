from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.services.remediation import (
    ACTION_TYPE_AI_FIX,
    ACTION_TYPE_GITHUB_ISSUE,
    OPEN_REMEDIATION_STATUSES,
)

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.get("/candidates", response_model=schemas.CursorPage)
def list_remediation_candidates(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    open_issue_exists = (
        select(models.RemediationAction.id)
        .where(
            models.RemediationAction.finding_id == models.Finding.id,
            models.RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            models.RemediationAction.provider == "github",
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
            models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
            models.Finding.fixed_version.is_not(None),
            models.Repository.provider == models.RepositoryProvider.github,
            ~open_issue_exists,
        )
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc())
        .limit(min(limit, 100))
    )

    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        items.append(
            schemas.RemediationCandidateOut(
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


@router.get("/issues", response_model=schemas.CursorPage)
def list_github_issue_actions(
    limit: int = 50,
    status: str | None = None,
    severity: models.Severity | None = None,
    finding_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = _remediation_action_context_stmt().where(
        models.RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
        models.RemediationAction.provider == "github",
    )
    if status:
        stmt = stmt.where(models.RemediationAction.status == status)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if finding_id:
        stmt = stmt.where(models.RemediationAction.finding_id == finding_id)
    stmt = stmt.order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc()).limit(
        min(limit, 100)
    )

    items = []
    for action, finding, application, vulnerability, component in db.execute(stmt):
        metadata = action.metadata_json or {}
        items.append(
            schemas.GitHubIssueActionOut(
                **_remediation_action_payload(action, finding, application, vulnerability, component),
                error=metadata.get("error"),
                close_error=metadata.get("close_error"),
                github_issue_url=metadata.get("github_issue_url") or metadata.get("html_url") or action.url,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/validations", response_model=schemas.CursorPage)
def list_remediation_validations(
    limit: int = 50,
    validation_status: str | None = None,
    action_type: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = _remediation_action_context_stmt()
    if action_type:
        stmt = stmt.where(models.RemediationAction.action_type == action_type)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = stmt.order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc()).limit(
        min(limit, 100)
    )

    items = []
    for action, finding, application, vulnerability, component in db.execute(stmt):
        metadata = action.metadata_json or {}
        status_value = str(metadata.get("validation_status") or "pending")
        if validation_status and status_value != validation_status:
            continue
        items.append(
            schemas.RemediationValidationOut(
                **_remediation_action_payload(action, finding, application, vulnerability, component),
                validation_status=status_value,
                validation_scan_id=_optional_uuid(metadata.get("validation_scan_id")),
                validation_scan_status=_optional_scan_status(metadata.get("validation_scan_status")),
                validation_error=metadata.get("validation_error"),
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/closures", response_model=schemas.CursorPage)
def list_issue_closures(
    limit: int = 50,
    close_state: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
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
        .where(models.Finding.status == models.FindingStatus.resolved)
        .order_by(models.Finding.resolved_at.desc().nullslast(), models.Finding.updated_at.desc())
    )
    actions_by_finding = _issue_actions_by_finding(db)

    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        action = actions_by_finding.get(finding.id)
        state = _close_state(action)
        if close_state and state != close_state:
            continue
        metadata = action.metadata_json if action else {}
        items.append(
            schemas.IssueClosureOut(
                finding_id=finding.id,
                finding_status=finding.status,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                vulnerability_external_id=vulnerability.external_id,
                component_name=component.name,
                action_id=action.id if action else None,
                provider_id=action.provider_id if action else None,
                url=action.url if action else None,
                close_state=state,
                close_error=metadata.get("close_error") if metadata else None,
                github_issue_closed_at=metadata.get("github_issue_closed_at") if metadata else None,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/prs", response_model=schemas.CursorPage)
def list_remediation_prs(
    limit: int = 50,
    status: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = _remediation_action_context_stmt()
    if status:
        stmt = stmt.where(models.RemediationAction.status == status)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    stmt = stmt.order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())
    items = []
    for action, finding, application, vulnerability, component in db.execute(stmt):
        if not _has_pr_signal(action):
            continue
        repository = db.get(models.Repository, application.repository_id)
        metadata = action.metadata_json or {}
        items.append(
            schemas.RemediationPrOut(
                action_id=action.id,
                action_type=action.action_type,
                action_status=action.status,
                finding_id=finding.id,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                provider_id=action.provider_id,
                branch=action.branch,
                url=_pr_url(action),
                ci_passed=_metadata_bool_or_none(metadata.get("ci_passed")),
                created_at=action.created_at,
                updated_at=action.updated_at,
            ).model_dump(mode="json")
        )
        if len(items) >= min(limit, 100):
            break
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/dependency-updates", response_model=schemas.CursorPage)
def list_dependency_updates(
    limit: int = 50,
    provider: str | None = None,
    ci_failed: bool | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = dependency_update_items(db)
    if provider:
        items = [item for item in items if item["provider"] == provider]
    if ci_failed is not None:
        items = [item for item in items if (item["ci_passed"] is False) is ci_failed]
    if status:
        items = [item for item in items if item["action_status"] == status]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/backlog", response_model=schemas.CursorPage)
def list_remediation_backlog(
    limit: int = 50,
    status: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_backlog_items(db)
    if status:
        items = [item for item in items if item["action_status"] == status]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/rescans", response_model=schemas.CursorPage)
def list_remediation_rescans(
    limit: int = 50,
    missing: bool | None = None,
    validation_status: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_rescan_items(db)
    if missing is not None:
        items = [item for item in items if item["missing_rescan"] is missing]
    if validation_status:
        items = [item for item in items if item["validation_status"] == validation_status]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def stale_remediation_count(db: Session) -> int:
    return len(remediation_backlog_items(db))


def dependency_update_items(db: Session) -> list[dict]:
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.desc(),
        models.RemediationAction.id.asc(),
    )
    for action, _, application, _, _ in db.execute(stmt):
        if not _has_dependency_update_signal(action):
            continue
        repository = db.get(models.Repository, application.repository_id)
        metadata = action.metadata_json or {}
        items.append(
            schemas.DependencyUpdateOut(
                action_id=action.id,
                provider=action.provider,
                update_source=_dependency_update_source(action),
                action_status=action.status,
                ci_passed=_metadata_bool_or_none(metadata.get("ci_passed")),
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                branch=action.branch,
                url=_pr_url(action),
                detail=str(metadata.get("update_kind") or metadata.get("dependency") or action.fixed_version or action.action_type),
            ).model_dump(mode="json")
        )
    return items


def remediation_backlog_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=7)
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.asc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        failed = action.status in {"failed", "close_failed"}
        stale = action.status in _BACKLOG_OPEN_STATUSES and _before(action.updated_at, cutoff)
        if not failed and not stale:
            continue
        repository = db.get(models.Repository, application.repository_id)
        reason = "failed" if failed else "stale_open"
        metadata = action.metadata_json or {}
        items.append(
            schemas.RemediationBacklogOut(
                action_id=action.id,
                action_type=action.action_type,
                action_status=action.status,
                finding_id=finding.id,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                age_days=max((now.replace(tzinfo=None) - action.updated_at.replace(tzinfo=None)).days, 0),
                reason=reason,
                detail=metadata.get("error") or metadata.get("close_error") or metadata.get("validation_error"),
                updated_at=action.updated_at,
            ).model_dump(mode="json")
        )
    return items


def remediation_rescan_items(db: Session) -> list[dict]:
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.created_at.desc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        metadata = action.metadata_json or {}
        validation_scan = _scan_from_metadata(db, metadata)
        latest_rescan = validation_scan or _latest_scan_after(db, application.id, action.created_at)
        repository = db.get(models.Repository, application.repository_id)
        validation_status = str(metadata.get("validation_status") or "pending")
        items.append(
            schemas.RemediationRescanOut(
                action_id=action.id,
                action_type=action.action_type,
                action_status=action.status,
                finding_id=finding.id,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                validation_status=validation_status,
                validation_scan_id=validation_scan.id if validation_scan else None,
                validation_scan_status=validation_scan.status if validation_scan else _optional_scan_status(
                    metadata.get("validation_scan_status")
                ),
                latest_rescan_id=latest_rescan.id if latest_rescan else None,
                latest_rescan_status=latest_rescan.status if latest_rescan else None,
                latest_rescan_created_at=latest_rescan.created_at if latest_rescan else None,
                missing_rescan=latest_rescan is None,
            ).model_dump(mode="json")
        )
    return items


def _remediation_action_context_stmt():
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


def _remediation_action_payload(
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


def _issue_actions_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    stmt = (
        select(models.RemediationAction)
        .where(
            models.RemediationAction.action_type == ACTION_TYPE_GITHUB_ISSUE,
            models.RemediationAction.provider == "github",
        )
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.desc())
    )
    actions = {}
    for action in db.execute(stmt).scalars():
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


_BACKLOG_OPEN_STATUSES = OPEN_REMEDIATION_STATUSES | {"running", "pending", "open", "queued"}


def _has_pr_signal(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    return bool(
        action.action_type in {ACTION_TYPE_AI_FIX, ACTION_TYPE_GITHUB_ISSUE}
        and (
            action.branch
            or action.url
            or action.provider_id
            or metadata.get("pull_request_url")
            or metadata.get("pr_number")
        )
    )


def _has_dependency_update_signal(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    searchable = " ".join(
        str(value or "")
        for value in [
            action.provider,
            action.branch,
            action.url,
            metadata.get("pull_request_url"),
            metadata.get("update_kind"),
            metadata.get("dependency"),
            metadata.get("source"),
        ]
    ).lower()
    return bool(
        "renovate" in searchable
        or "dependabot" in searchable
        or metadata.get("pull_request_url")
        or metadata.get("update_kind")
        or "ci_passed" in metadata
    )


def _dependency_update_source(action: models.RemediationAction) -> str:
    metadata = action.metadata_json or {}
    searchable = f"{action.provider or ''} {action.branch or ''} {action.url or ''} {metadata}".lower()
    if "renovate" in searchable:
        return "renovate"
    if "dependabot" in searchable:
        return "dependabot"
    if action.action_type == ACTION_TYPE_AI_FIX:
        return "ai_fix"
    return "dependency_update"


def _pr_url(action: models.RemediationAction) -> str | None:
    metadata = action.metadata_json or {}
    return metadata.get("pull_request_url") or metadata.get("github_issue_url") or metadata.get("html_url") or action.url


def _metadata_bool_or_none(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _scan_from_metadata(db: Session, metadata: dict) -> models.Scan | None:
    scan_id = _optional_uuid(metadata.get("validation_scan_id"))
    return db.get(models.Scan, scan_id) if scan_id else None


def _latest_scan_after(db: Session, application_id: UUID, created_at: datetime) -> models.Scan | None:
    scans = db.scalars(
        select(models.Scan)
        .where(models.Scan.application_id == application_id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
    )
    for scan in scans:
        if not _before(scan.created_at, created_at) and scan.created_at != created_at:
            return scan
    return None


def _optional_uuid(value: object) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(str(value))
    except ValueError:
        return None


def _optional_scan_status(value: object) -> models.ScanStatus | None:
    if not value:
        return None
    try:
        return models.ScanStatus(str(value))
    except ValueError:
        return None
