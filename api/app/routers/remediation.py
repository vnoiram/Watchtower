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
from api.app.routers.sla import is_sla_breached

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


@router.get("/pr-staleness", response_model=schemas.CursorPage)
def list_pr_staleness(
    limit: int = 50,
    staleness_type: str | None = None,
    severity: models.Severity | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = pr_staleness_items(db)
    if staleness_type:
        items = [item for item in items if item["staleness_type"] == staleness_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if status:
        items = [item for item in items if item["action_status"] == status]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


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


@router.get("/dependency-update-coverage", response_model=schemas.CursorPage)
def list_dependency_update_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    severity: models.Severity | None = None,
    provider: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = dependency_update_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if provider:
        items = [item for item in items if item["provider"] == provider]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/priority-queue", response_model=schemas.CursorPage)
def list_remediation_priority_queue(
    limit: int = 50,
    severity: models.Severity | None = None,
    sla_breached: bool | None = None,
    fix_available: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_priority_queue_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if sla_breached is not None:
        items = [item for item in items if item["sla_breached"] is sla_breached]
    if fix_available is not None:
        items = [item for item in items if item["fix_available"] is fix_available]
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


@router.get("/coverage", response_model=schemas.CursorPage)
def list_remediation_coverage(
    limit: int = 50,
    missing_action: bool | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_coverage_items(db)
    if missing_action is not None:
        items = [item for item in items if item["has_issue_or_pr"] is not missing_action]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/fixable-gaps", response_model=schemas.CursorPage)
def list_fixable_gaps(
    limit: int = 50,
    gap_type: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = fixable_gap_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/pr-ci-failures", response_model=schemas.CursorPage)
def list_pr_ci_failures(
    limit: int = 50,
    severity: models.Severity | None = None,
    provider: str | None = None,
    action_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = pr_ci_failure_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if provider:
        items = [item for item in items if item["provider"] == provider]
    if action_type:
        items = [item for item in items if item["action_type"] == action_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/provider-sync", response_model=schemas.CursorPage)
def list_provider_sync_evidence(
    limit: int = 50,
    gap_type: str | None = None,
    provider: str | None = None,
    action_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = provider_sync_evidence_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if provider:
        items = [item for item in items if item["provider"] == provider]
    if action_type:
        items = [item for item in items if item["action_type"] == action_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/issue-slo", response_model=schemas.CursorPage)
def list_issue_creation_slo(
    limit: int = 50,
    breached: bool | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = issue_creation_slo_items(db)
    if breached is not None:
        items = [item for item in items if item["breached"] is breached]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/auto-resolution", response_model=schemas.CursorPage)
def list_auto_resolution_evidence(
    limit: int = 50,
    complete: bool | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = auto_resolution_evidence_items(db)
    if complete is not None:
        items = [item for item in items if item["complete"] is complete]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/evidence-chain", response_model=schemas.CursorPage)
def list_remediation_evidence_chain(
    limit: int = 50,
    severity: models.Severity | None = None,
    status: models.FindingStatus | None = None,
    missing_stage: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_evidence_chain_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if status:
        items = [item for item in items if item["status"] == status.value]
    if missing_stage:
        items = [item for item in items if missing_stage in item["missing_stages"]]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/resolution-verification", response_model=schemas.CursorPage)
def list_resolution_verification(
    limit: int = 50,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = resolution_verification_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/aging", response_model=schemas.CursorPage)
def list_remediation_aging(
    limit: int = 50,
    age_bucket: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = remediation_aging_items(db)
    if age_bucket:
        items = [item for item in items if item["age_bucket"] == age_bucket]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/suppressions", response_model=schemas.CursorPage)
def list_automation_suppressions(
    limit: int = 50,
    reason: str | None = None,
    action_type: str | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = automation_suppression_items(db)
    if reason:
        items = [item for item in items if item["reason"] == reason]
    if action_type:
        items = [item for item in items if item["action_type"] == action_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def stale_remediation_count(db: Session) -> int:
    return len(remediation_backlog_items(db))


def remediation_coverage_count(db: Session) -> int:
    return sum(1 for item in remediation_coverage_items(db) if not item["has_issue_or_pr"])


def fixable_gap_count(db: Session) -> int:
    return len(fixable_gap_items(db))


def pr_ci_failure_count(db: Session) -> int:
    return len(pr_ci_failure_items(db))


def provider_sync_gap_count(db: Session) -> int:
    return len(provider_sync_evidence_items(db))


def issue_slo_breach_count(db: Session) -> int:
    return sum(1 for item in issue_creation_slo_items(db) if item["breached"])


def auto_resolution_gap_count(db: Session) -> int:
    return sum(1 for item in auto_resolution_evidence_items(db) if not item["complete"])


def remediation_evidence_gap_count(db: Session) -> int:
    return sum(1 for item in remediation_evidence_chain_items(db) if item["missing_stages"])


def pr_staleness_count(db: Session) -> int:
    return len(pr_staleness_items(db))


def pr_staleness_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=7)
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.asc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        if not _has_pr_signal(action):
            continue
        metadata = action.metadata_json or {}
        ci_passed = _metadata_bool_or_none(metadata.get("ci_passed"))
        age_days = max((now.replace(tzinfo=None) - action.updated_at.replace(tzinfo=None)).days, 0)
        repository = db.get(models.Repository, application.repository_id)
        context = (action, finding, application, repository, vulnerability, component, ci_passed, age_days)
        if action.status in _BACKLOG_OPEN_STATUSES and _before(action.updated_at, stale_cutoff):
            items.append(_pr_staleness_item("stale_pr", *context, detail="PR action has not been updated in 7 days"))
        if ci_passed is not True:
            items.append(_pr_staleness_item("ci_incomplete", *context, detail="PR action is missing successful CI evidence"))
        if action.status in {"created", "open", "in_review", "pending_review"}:
            items.append(_pr_staleness_item("review_or_merge_waiting", *context, detail="PR action is waiting for review or merge"))
    return items


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


def provider_sync_evidence_items(db: Session) -> list[dict]:
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.desc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        if action.action_type != ACTION_TYPE_GITHUB_ISSUE and not _has_pr_signal(action):
            continue
        repository = db.get(models.Repository, application.repository_id)
        metadata = action.metadata_json or {}
        url = _pr_url(action)
        if not action.provider_id:
            items.append(_provider_sync_item("missing_provider_id", action, finding, application, repository, "Remediation action has no external provider id"))
        if not url:
            items.append(_provider_sync_item("missing_url", action, finding, application, repository, "Remediation action has no external URL"))
        if not any(key in metadata for key in ["provider_status", "github_state", "state", "last_synced_at", "synced_at"]):
            items.append(_provider_sync_item("missing_status_sync", action, finding, application, repository, "Remediation action has no provider status sync metadata"))
        if action.status in {"closed", "resolved", "merged"} and not any(key in metadata for key in ["github_issue_closed_at", "closed_at", "merged_at"]):
            items.append(_provider_sync_item("missing_close_evidence", action, finding, application, repository, "Closed or merged action has no close evidence timestamp"))
        if _has_pr_signal(action) and "ci_passed" not in metadata and "workflow_conclusion" not in metadata:
            items.append(_provider_sync_item("missing_ci_metadata", action, finding, application, repository, "PR action has no CI metadata"))
    return items


def dependency_update_gap_count(db: Session) -> int:
    return len(dependency_update_coverage_items(db))


def remediation_priority_count(db: Session) -> int:
    return len(remediation_priority_queue_items(db))


def dependency_update_coverage_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=7)
    action_by_finding = _latest_dependency_update_action_by_finding(db)
    items = []
    for finding, application, repository, component, vulnerability in _fixed_findings(db):
        action = action_by_finding.get(finding.id)
        if action is None:
            items.append(
                _dependency_update_coverage_item(
                    "missing_update_action",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    None,
                    now,
                    "Fixable finding has no dependency update action",
                )
            )
            continue
        metadata = action.metadata_json or {}
        validation_scan = _scan_from_metadata(db, metadata)
        validation_status = str(metadata.get("validation_status") or "")
        detail = metadata.get("error") or metadata.get("validation_error") or metadata.get("ci_error")
        if action.status in {"failed", "close_failed"}:
            items.append(
                _dependency_update_coverage_item(
                    "failed_update_action",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    action,
                    now,
                    str(detail or "Dependency update action failed"),
                )
            )
        elif action.status in _BACKLOG_OPEN_STATUSES and _before(action.updated_at, stale_cutoff):
            items.append(
                _dependency_update_coverage_item(
                    "stale_update_action",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    action,
                    now,
                    "Dependency update action has been open for more than 7 days",
                )
            )
        if validation_scan is None and validation_status not in {"succeeded", "passed"}:
            items.append(
                _dependency_update_coverage_item(
                    "missing_validation_scan",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    action,
                    now,
                    "Dependency update has no validation scan evidence",
                )
            )
    return items


def remediation_priority_queue_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status.in_([models.FindingStatus.open, models.FindingStatus.triaged, models.FindingStatus.in_progress]))
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        rank, reasons = _priority_rank(finding, application, vulnerability, now)
        items.append(
            schemas.RemediationPriorityQueueOut(
                finding_id=finding.id,
                severity=finding.severity,
                status=finding.status,
                risk_score=finding.risk_score,
                priority_rank=rank,
                priority_reason=", ".join(reasons),
                sla_breached=is_sla_breached(finding, now),
                fix_available=bool(finding.fixed_version),
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                production=application.production,
                internet_exposed=application.internet_exposed,
                has_kev=_vulnerability_has(vulnerability, {"kev", "cisa"}),
                has_exploit=_vulnerability_has(vulnerability, {"exploit", "poc", "proof-of-concept"}),
                fixed_version=finding.fixed_version,
                created_at=finding.created_at,
            ).model_dump(mode="json")
        )
    return sorted(items, key=lambda item: (-item["priority_rank"], item["created_at"], item["finding_id"]))


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


def remediation_coverage_items(db: Session) -> list[dict]:
    rows = list(_fixed_critical_high_findings(db))
    action_by_finding = _latest_issue_or_pr_action_by_finding(db)
    covered = sum(1 for finding, *_ in rows if finding.id in action_by_finding)
    coverage_percent = _percent(covered, len(rows))
    items = []
    for finding, application, repository, component, vulnerability in rows:
        action = action_by_finding.get(finding.id)
        items.append(
            schemas.RemediationCoverageOut(
                finding_id=finding.id,
                severity=finding.severity,
                risk_score=finding.risk_score,
                fixed_version=finding.fixed_version or "",
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                has_issue_or_pr=action is not None,
                action_id=action.id if action else None,
                action_type=action.action_type if action else None,
                action_status=action.status if action else None,
                provider=action.provider if action else None,
                url=_pr_url(action) if action else None,
                coverage_percent=coverage_percent,
            ).model_dump(mode="json")
        )
    return items


def fixable_gap_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=7)
    action_by_finding = _latest_issue_or_pr_action_by_finding(db)
    items = []
    for finding, application, repository, component, vulnerability in _fixed_critical_high_findings(db):
        action = action_by_finding.get(finding.id)
        if action is None:
            items.append(
                _fixable_gap_item(
                    "missing_issue_or_pr",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    None,
                    finding.updated_at,
                    "Fixable critical/high finding has no Issue or PR action",
                )
            )
            continue
        metadata = action.metadata_json or {}
        detail = metadata.get("error") or metadata.get("close_error") or metadata.get("validation_error")
        if action.status in {"failed", "close_failed"}:
            items.append(
                _fixable_gap_item(
                    "failed_action",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    action,
                    action.updated_at,
                    str(detail or "Remediation action failed"),
                )
            )
        elif action.status in _BACKLOG_OPEN_STATUSES and _before(action.updated_at, stale_cutoff):
            items.append(
                _fixable_gap_item(
                    "stale_action",
                    finding,
                    application,
                    repository,
                    component,
                    vulnerability,
                    action,
                    action.updated_at,
                    "Remediation action has been open for more than 7 days",
                )
            )
    return items


def pr_ci_failure_items(db: Session) -> list[dict]:
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.desc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, _, _ in db.execute(stmt):
        if not _has_pr_signal(action):
            continue
        metadata = action.metadata_json or {}
        detail = _ci_failure_detail(action)
        if detail is None:
            continue
        repository = db.get(models.Repository, application.repository_id)
        items.append(
            schemas.PrCiFailureOut(
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
                provider=action.provider,
                provider_id=action.provider_id,
                branch=action.branch,
                url=_pr_url(action),
                ci_passed=_metadata_bool_or_none(metadata.get("ci_passed")),
                detail=detail,
                updated_at=action.updated_at,
            ).model_dump(mode="json")
        )
    return items


def issue_creation_slo_items(db: Session) -> list[dict]:
    notification_evidence = _sent_notification_evidence_by_finding(db)
    action_evidence = _first_issue_or_pr_action_by_finding(db)
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(
            models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
            models.Finding.status == models.FindingStatus.open,
        )
        .order_by(models.Finding.created_at.asc(), models.Finding.id.asc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        deadline = finding.created_at + timedelta(hours=1 if finding.severity == models.Severity.critical else 24)
        notification = notification_evidence.get(finding.id)
        action = action_evidence.get(finding.id)
        evidence_candidates = []
        if notification and notification.sent_at:
            evidence_candidates.append(("notification", notification.sent_at, None))
        if action:
            evidence_candidates.append(("issue_or_pr", action.created_at, action))
        evidence = min(evidence_candidates, key=lambda item: item[1]) if evidence_candidates else None
        evidence_type = evidence[0] if evidence else None
        evidence_at = evidence[1] if evidence else None
        evidence_action = evidence[2] if evidence else None
        breached = evidence_at is None or _after(evidence_at, deadline)
        items.append(
            schemas.IssueCreationSloOut(
                finding_id=finding.id,
                severity=finding.severity,
                finding_status=finding.status,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                created_at=finding.created_at,
                deadline_at=deadline,
                first_evidence_at=evidence_at,
                evidence_type=evidence_type,
                action_id=evidence_action.id if evidence_action else None,
                breached=breached,
                detail="Issue creation SLO is satisfied" if not breached else "Notification, Issue, or PR evidence is missing or late",
            ).model_dump(mode="json")
        )
    return items


def auto_resolution_evidence_items(db: Session) -> list[dict]:
    actions_by_finding = _actions_by_finding(db)
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status == models.FindingStatus.resolved)
        .order_by(models.Finding.resolved_at.desc().nullslast(), models.Finding.updated_at.desc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        actions = actions_by_finding.get(finding.id, [])
        successful_action = next((action for action in actions if _successful_action(action)), None)
        validation_scan = next((_scan_from_metadata(db, action.metadata_json or {}) for action in actions if _scan_from_metadata(db, action.metadata_json or {})), None)
        issue_action = next((action for action in actions if action.action_type == ACTION_TYPE_GITHUB_ISSUE), None)
        close_state = _close_state(issue_action)
        complete = successful_action is not None and validation_scan is not None and close_state == "closed"
        items.append(
            schemas.AutoResolutionEvidenceOut(
                finding_id=finding.id,
                severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                resolved_at=finding.resolved_at,
                successful_action_id=successful_action.id if successful_action else None,
                validation_scan_id=validation_scan.id if validation_scan else None,
                validation_scan_status=validation_scan.status if validation_scan else None,
                issue_action_id=issue_action.id if issue_action else None,
                close_state=close_state,
                complete=complete,
                detail="Auto-resolution evidence is complete" if complete else "Resolved finding is missing action, validation, or closure evidence",
            ).model_dump(mode="json")
        )
    return items


def remediation_evidence_chain_items(db: Session) -> list[dict]:
    notifications = _sent_notification_evidence_by_finding(db)
    issue_or_pr_actions = _first_issue_or_pr_action_by_finding(db)
    actions_by_finding = _actions_by_finding(db)
    stmt = (
        select(models.Finding, models.Application, models.Repository)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Finding.severity.in_([models.Severity.critical, models.Severity.high]))
        .order_by(models.Finding.created_at.asc(), models.Finding.id.asc())
    )
    items = []
    for finding, application, repository in db.execute(stmt):
        notification = notifications.get(finding.id)
        issue_or_pr = issue_or_pr_actions.get(finding.id)
        actions = actions_by_finding.get(finding.id, [])
        validation_action = next((action for action in actions if _scan_from_metadata(db, action.metadata_json or {}) or (action.metadata_json or {}).get("validation_status")), None)
        validation_scan = _scan_from_metadata(db, validation_action.metadata_json or {}) if validation_action else None
        validation_status = str((validation_action.metadata_json or {}).get("validation_status")) if validation_action and (validation_action.metadata_json or {}).get("validation_status") else None
        closure_action = next((action for action in actions if action.status == "closed" or (action.metadata_json or {}).get("github_issue_closed_at")), None)
        missing = []
        if notification is None:
            missing.append("notification")
        if issue_or_pr is None:
            missing.append("issue_or_pr")
        if validation_action is None:
            missing.append("validation")
        if finding.status == models.FindingStatus.resolved and closure_action is None:
            missing.append("closure")
        closure_status = "closed" if closure_action else ("not_required" if finding.status != models.FindingStatus.resolved else "missing")
        items.append(
            schemas.RemediationEvidenceChainOut(
                finding_id=finding.id,
                severity=finding.severity,
                status=finding.status,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                notification_id=notification.id if notification else None,
                issue_or_pr_action_id=issue_or_pr.id if issue_or_pr else None,
                validation_status=validation_status,
                validation_scan_id=validation_scan.id if validation_scan else None,
                validation_scan_status=validation_scan.status if validation_scan else None,
                closure_status=closure_status,
                missing_stages=missing,
                detail="Remediation evidence chain is complete" if not missing else f"Missing {', '.join(missing)}",
            ).model_dump(mode="json")
        )
    return items


def resolution_verification_items(db: Session) -> list[dict]:
    items = []
    issue_actions = _issue_actions_by_finding(db)
    for action, finding, application, vulnerability, component in db.execute(_remediation_action_context_stmt()):
        metadata = action.metadata_json or {}
        validation_status = str(metadata.get("validation_status") or "pending")
        validation_scan = _scan_from_metadata(db, metadata)
        latest_rescan = validation_scan or _latest_scan_after(db, application.id, action.created_at)
        repository = db.get(models.Repository, application.repository_id)
        close_state = _close_state(issue_actions.get(finding.id))
        if latest_rescan is None:
            items.append(
                _resolution_verification_item(
                    "missing_rescan",
                    "Remediation action has no validation or later rescan",
                    action,
                    finding,
                    application,
                    repository,
                    validation_status,
                    validation_scan,
                    latest_rescan,
                    close_state,
                )
            )
        if validation_status in {"failed", "error"} or (validation_scan and validation_scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out}):
            items.append(
                _resolution_verification_item(
                    "failed_validation",
                    "Validation scan or validation status failed",
                    action,
                    finding,
                    application,
                    repository,
                    validation_status,
                    validation_scan,
                    latest_rescan,
                    close_state,
                )
            )
        if finding.status == models.FindingStatus.resolved and close_state != "closed":
            items.append(
                _resolution_verification_item(
                    "missing_issue_close",
                    "Resolved finding does not have a closed GitHub issue action",
                    action,
                    finding,
                    application,
                    repository,
                    validation_status,
                    validation_scan,
                    latest_rescan,
                    close_state,
                )
            )
    return items


def remediation_aging_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.asc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        if action.status not in _BACKLOG_OPEN_STATUSES and action.status not in {"failed", "close_failed"}:
            continue
        age_days = max((now.replace(tzinfo=None) - action.updated_at.replace(tzinfo=None)).days, 0)
        bucket = _age_bucket(age_days)
        if bucket == "fresh":
            continue
        repository = db.get(models.Repository, application.repository_id)
        items.append(
            schemas.RemediationAgingOut(
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
                age_days=age_days,
                age_bucket=bucket,
                url=_pr_url(action),
                updated_at=action.updated_at,
            ).model_dump(mode="json")
        )
    return items


def automation_suppression_items(db: Session) -> list[dict]:
    items = []
    stmt = _remediation_action_context_stmt().order_by(
        models.RemediationAction.updated_at.desc(),
        models.RemediationAction.id.asc(),
    )
    for action, finding, application, vulnerability, component in db.execute(stmt):
        metadata = action.metadata_json or {}
        reason = _suppression_reason(action)
        if not reason:
            continue
        repository = db.get(models.Repository, application.repository_id)
        detail = (
            metadata.get("skipped_reason")
            or metadata.get("block_reason")
            or metadata.get("policy_reason")
            or metadata.get("duplicate_of")
            or action.status
        )
        items.append(
            schemas.AutomationSuppressionOut(
                reason=reason,
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
                duplicate_of=metadata.get("duplicate_of"),
                policy_reason=metadata.get("policy_reason"),
                detail=str(detail),
                updated_at=action.updated_at,
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


def _fixable_gap_item(
    gap_type: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    action: models.RemediationAction | None,
    updated_at: datetime,
    detail: str,
) -> dict:
    return schemas.FixableGapOut(
        gap_type=gap_type,
        finding_id=finding.id,
        severity=finding.severity,
        risk_score=finding.risk_score,
        fixed_version=finding.fixed_version or "",
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        component_version=component.version,
        vulnerability_external_id=vulnerability.external_id,
        action_id=action.id if action else None,
        action_type=action.action_type if action else None,
        action_status=action.status if action else None,
        updated_at=updated_at,
        detail=detail,
    ).model_dump(mode="json")


def _fixed_critical_high_findings(db: Session):
    return db.execute(
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
        )
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc())
    )


def _fixed_findings(db: Session):
    return db.execute(
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
            models.Finding.status.in_([models.FindingStatus.open, models.FindingStatus.triaged, models.FindingStatus.in_progress]),
            models.Finding.fixed_version.is_not(None),
        )
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc(), models.Finding.id.asc())
    )


def _latest_issue_or_pr_action_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    actions = {}
    stmt = select(models.RemediationAction).order_by(
        models.RemediationAction.created_at.desc(),
        models.RemediationAction.id.desc(),
    )
    for action in db.scalars(stmt):
        if action.action_type == ACTION_TYPE_GITHUB_ISSUE or _has_pr_signal(action):
            actions.setdefault(action.finding_id, action)
    return actions


def _latest_dependency_update_action_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    actions = {}
    stmt = select(models.RemediationAction).order_by(
        models.RemediationAction.created_at.desc(),
        models.RemediationAction.id.desc(),
    )
    for action in db.scalars(stmt):
        if _has_dependency_update_signal(action) or action.action_type in {ACTION_TYPE_AI_FIX, ACTION_TYPE_GITHUB_ISSUE}:
            actions.setdefault(action.finding_id, action)
    return actions


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


def _resolution_verification_item(
    issue_type: str,
    detail: str,
    action: models.RemediationAction,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    validation_status: str,
    validation_scan: models.Scan | None,
    latest_rescan: models.Scan | None,
    close_state: str,
) -> dict:
    return schemas.ResolutionVerificationOut(
        issue_type=issue_type,
        finding_id=finding.id,
        severity=finding.severity,
        finding_status=finding.status,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        action_id=action.id,
        action_type=action.action_type,
        action_status=action.status,
        validation_status=validation_status,
        validation_scan_id=validation_scan.id if validation_scan else None,
        validation_scan_status=validation_scan.status if validation_scan else None,
        latest_rescan_id=latest_rescan.id if latest_rescan else None,
        latest_rescan_status=latest_rescan.status if latest_rescan else None,
        close_state=close_state,
        detail=detail,
    ).model_dump(mode="json")


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


def _actions_by_finding(db: Session) -> dict[UUID, list[models.RemediationAction]]:
    actions: dict[UUID, list[models.RemediationAction]] = {}
    stmt = select(models.RemediationAction).order_by(
        models.RemediationAction.created_at.asc(),
        models.RemediationAction.id.asc(),
    )
    for action in db.scalars(stmt):
        actions.setdefault(action.finding_id, []).append(action)
    return actions


def _sent_notification_evidence_by_finding(db: Session) -> dict[UUID, models.Notification]:
    notifications = {}
    stmt = (
        select(models.Notification)
        .where(models.Notification.status == "sent")
        .order_by(models.Notification.sent_at.asc().nullslast(), models.Notification.created_at.asc())
    )
    for notification in db.scalars(stmt):
        finding_id = _optional_uuid((notification.metadata_json or {}).get("finding_id"))
        if finding_id is not None:
            notifications.setdefault(finding_id, notification)
    return notifications


def _first_issue_or_pr_action_by_finding(db: Session) -> dict[UUID, models.RemediationAction]:
    actions = {}
    stmt = select(models.RemediationAction).order_by(
        models.RemediationAction.created_at.asc(),
        models.RemediationAction.id.asc(),
    )
    for action in db.scalars(stmt):
        if action.action_type == ACTION_TYPE_GITHUB_ISSUE or _has_pr_signal(action):
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


def _provider_sync_item(
    gap_type: str,
    action: models.RemediationAction,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    detail: str,
) -> dict:
    return schemas.ProviderSyncEvidenceOut(
        gap_type=gap_type,
        action_id=action.id,
        action_type=action.action_type,
        action_status=action.status,
        provider=action.provider,
        provider_id=action.provider_id,
        url=_pr_url(action),
        finding_id=finding.id,
        severity=finding.severity,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        detail=detail,
        updated_at=action.updated_at,
    ).model_dump(mode="json")


def _pr_staleness_item(
    staleness_type: str,
    action: models.RemediationAction,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    vulnerability: models.Vulnerability,
    component: models.Component,
    ci_passed: bool | None,
    age_days: int,
    detail: str,
) -> dict:
    return schemas.PrStalenessOut(
        staleness_type=staleness_type,
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
        ci_passed=ci_passed,
        age_days=age_days,
        detail=f"{detail}: {component.name} / {vulnerability.external_id}",
        updated_at=action.updated_at,
    ).model_dump(mode="json")


def _suppression_reason(action: models.RemediationAction) -> str | None:
    metadata = action.metadata_json or {}
    if action.status == "skipped_duplicate" or metadata.get("duplicate_of"):
        return "duplicate"
    if action.status == "blocked" or metadata.get("block_reason"):
        return "blocked"
    if action.status == "cancelled":
        return "cancelled"
    if metadata.get("skipped_reason"):
        return "skipped"
    if metadata.get("policy_reason"):
        return "policy"
    return None


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


def _dependency_update_coverage_item(
    gap_type: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    action: models.RemediationAction | None,
    now: datetime,
    detail: str,
) -> dict:
    metadata = action.metadata_json if action else {}
    reference_time = action.updated_at if action else finding.updated_at
    comparable_now = _matching_datetime(now, reference_time)
    return schemas.DependencyUpdateCoverageOut(
        gap_type=gap_type,
        finding_id=finding.id,
        severity=finding.severity,
        status=finding.status,
        risk_score=finding.risk_score,
        fixed_version=finding.fixed_version or "",
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        vulnerability_external_id=vulnerability.external_id,
        provider=action.provider if action else None,
        update_source=_dependency_update_source(action) if action else None,
        action_id=action.id if action else None,
        action_type=action.action_type if action else None,
        action_status=action.status if action else None,
        validation_status=str(metadata.get("validation_status")) if metadata.get("validation_status") else None,
        validation_scan_id=_optional_uuid(metadata.get("validation_scan_id")) if metadata else None,
        age_days=max((comparable_now - reference_time).days, 0),
        detail=detail,
    ).model_dump(mode="json")


def _priority_rank(
    finding: models.Finding,
    application: models.Application,
    vulnerability: models.Vulnerability,
    now: datetime,
) -> tuple[int, list[str]]:
    rank = int(finding.risk_score * 10)
    reasons = [f"risk_score:{finding.risk_score:g}"]
    severity_bonus = {
        models.Severity.critical: 50,
        models.Severity.high: 35,
        models.Severity.medium: 15,
        models.Severity.low: 5,
    }.get(finding.severity, 0)
    rank += severity_bonus
    reasons.append(f"severity:{finding.severity.value}")
    if is_sla_breached(finding, now):
        rank += 40
        reasons.append("sla_breached")
    if application.internet_exposed:
        rank += 25
        reasons.append("internet_exposed")
    if application.production:
        rank += 20
        reasons.append("production")
    if _vulnerability_has(vulnerability, {"kev", "cisa"}):
        rank += 30
        reasons.append("kev")
    if _vulnerability_has(vulnerability, {"exploit", "poc", "proof-of-concept"}):
        rank += 20
        reasons.append("exploit")
    if finding.fixed_version:
        rank += 10
        reasons.append("fix_available")
    return rank, reasons


def _vulnerability_has(vulnerability: models.Vulnerability, tokens: set[str]) -> bool:
    text = _flatten_evidence([vulnerability.title, vulnerability.description, vulnerability.references or []])
    return any(token in text for token in tokens)


def _flatten_evidence(value) -> str:
    if isinstance(value, dict):
        return " ".join([str(key).lower() for key in value] + [_flatten_evidence(item) for item in value.values()])
    if isinstance(value, list | tuple | set):
        return " ".join(_flatten_evidence(item) for item in value)
    return str(value or "").lower()


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference


def _ci_failure_detail(action: models.RemediationAction) -> str | None:
    metadata = action.metadata_json or {}
    if _metadata_bool_or_none(metadata.get("ci_passed")) is False:
        return str(metadata.get("ci_error") or metadata.get("error") or "CI reported failure")
    text = " ".join(
        str(value or "")
        for value in [
            action.status,
            metadata.get("ci_status"),
            metadata.get("validation_status"),
            metadata.get("ci_error"),
            metadata.get("error"),
            metadata.get("status"),
        ]
    ).lower()
    if "ci" in text and any(token in text for token in ["fail", "error", "red"]):
        return str(metadata.get("ci_error") or metadata.get("error") or action.status)
    return None


def _successful_action(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    return action.status in {"succeeded", "merged", "closed"} or metadata.get("validation_status") == "succeeded"


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


def _age_bucket(age_days: int) -> str:
    if age_days >= 30:
        return "long_stale"
    if age_days >= 7:
        return "stale"
    return "fresh"


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _after(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value > reference


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
