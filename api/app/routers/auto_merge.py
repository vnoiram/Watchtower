from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.services.automerge import evaluate_auto_merge

router = APIRouter(prefix="/auto-merge", tags=["auto-merge"])


@router.get("/eligibility", response_model=schemas.CursorPage)
def list_auto_merge_eligibility(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = (
        select(models.RemediationAction, models.Finding, models.Application, models.Repository)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())
        .limit(min(limit, 100))
    )

    items = []
    for action, finding, application, repository in db.execute(stmt):
        metadata = action.metadata_json or {}
        update_kind = str(metadata.get("update_kind") or "unknown")
        ci_passed = _metadata_bool(metadata.get("ci_passed"))
        validation_scan_resolved = metadata.get("validation_status") == "succeeded"
        tier_allows = _tier_allows(application, metadata)
        touches_forbidden_path = _metadata_bool(metadata.get("touches_forbidden_path"))
        decision = evaluate_auto_merge(
            enabled=application.auto_merge_enabled,
            dry_run=True,
            update_kind=update_kind,
            ci_passed=ci_passed,
            validation_scan_resolved=validation_scan_resolved,
            tier_allows=tier_allows,
            touches_forbidden_path=touches_forbidden_path,
        )
        items.append(
            schemas.AutoMergeEligibilityOut(
                action_id=action.id,
                action_type=action.action_type,
                action_status=action.status,
                finding_id=finding.id,
                finding_severity=finding.severity,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                allowed=decision.allowed,
                reason=decision.reason,
                dry_run=decision.dry_run,
                update_kind=update_kind,
                ci_passed=ci_passed,
                validation_scan_resolved=validation_scan_resolved,
                tier_allows=tier_allows,
                touches_forbidden_path=touches_forbidden_path,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/pilot-readiness", response_model=schemas.CursorPage)
def list_auto_merge_pilot_readiness(
    limit: int = 50,
    allowed: bool | None = None,
    reason: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = auto_merge_pilot_readiness_items(db)
    if allowed is not None:
        items = [item for item in items if item["allowed"] is allowed]
    if reason:
        items = [item for item in items if item["reason"] == reason]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/guardrails", response_model=list[schemas.AutomationGuardrailOut])
def automation_guardrails(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return automation_guardrail_items(db)


@router.get("/policy-violations", response_model=schemas.CursorPage)
def list_auto_merge_policy_violations(
    limit: int = 50,
    violation_type: str | None = None,
    severity: models.Severity | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = auto_merge_policy_violation_items(db)
    if violation_type:
        items = [item for item in items if item["violation_type"] == violation_type]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    if status:
        items = [item for item in items if item["action_status"] == status]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/dry-runs", response_model=schemas.CursorPage)
def list_auto_merge_dry_runs(
    limit: int = 50,
    decision: str | None = None,
    mismatch: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = auto_merge_dry_run_items(db)
    if decision:
        items = [item for item in items if item["decision"] == decision]
    if mismatch is not None:
        items = [item for item in items if item["mismatch"] is mismatch]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def automation_guardrail_count(db: Session) -> int:
    return sum(item.count for item in automation_guardrail_items(db) if item.status != "ok")


def auto_merge_pilot_readiness_items(db: Session) -> list[dict]:
    stmt = (
        select(models.RemediationAction, models.Finding, models.Application, models.Repository)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())
    )
    items = []
    for action, finding, application, repository in db.execute(stmt):
        metadata = action.metadata_json or {}
        update_kind = str(metadata.get("update_kind") or "unknown")
        ci_passed = _metadata_bool(metadata.get("ci_passed"))
        validation_scan_resolved = metadata.get("validation_status") == "succeeded"
        tier_allows = _tier_allows(application, metadata)
        touches_forbidden_path = _metadata_bool(metadata.get("touches_forbidden_path"))
        decision = evaluate_auto_merge(
            enabled=application.auto_merge_enabled,
            dry_run=True,
            update_kind=update_kind,
            ci_passed=ci_passed,
            validation_scan_resolved=validation_scan_resolved,
            tier_allows=tier_allows,
            touches_forbidden_path=touches_forbidden_path,
        )
        reason = _pilot_reason(application, decision.reason, ci_passed, validation_scan_resolved, tier_allows, touches_forbidden_path)
        items.append(
            schemas.AutoMergePilotReadinessOut(
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
                allowed=decision.allowed and reason == "eligible",
                reason=reason,
                ci_passed=ci_passed,
                validation_scan_resolved=validation_scan_resolved,
                tier_allows=tier_allows,
                touches_forbidden_path=touches_forbidden_path,
            ).model_dump(mode="json")
        )
    return items


def automation_guardrail_items(db: Session) -> list[schemas.AutomationGuardrailOut]:
    rows = list(db.execute(_automation_context_stmt()))
    audit_logs = list(db.scalars(select(models.AuditLog)))
    production_high = 0
    disabled = 0
    ci_missing = 0
    validation_missing = 0
    forbidden_path = 0
    tier_blocked = 0
    audit_missing = 0
    for action, finding, application, repository in rows:
        metadata = action.metadata_json or {}
        if application.production or application.criticality in {"high", "critical"}:
            production_high += 1
        if not application.auto_merge_enabled:
            disabled += 1
        if _metadata_bool_or_none(metadata.get("ci_passed")) is not True:
            ci_missing += 1
        if metadata.get("validation_status") != "succeeded":
            validation_missing += 1
        if _metadata_bool(metadata.get("touches_forbidden_path")):
            forbidden_path += 1
        if not _tier_allows(application, metadata):
            tier_blocked += 1
        if not _has_audit_log(audit_logs, "remediation_action", str(action.id)):
            audit_missing += 1
    return [
        _guardrail("production_high_criticality", "warn", production_high, "Automation actions touching production or high criticality applications"),
        _guardrail("auto_merge_disabled", "warn", disabled, "Automation actions where application auto-merge is disabled"),
        _guardrail("ci_not_passed", "fail", ci_missing, "Automation actions without successful CI evidence"),
        _guardrail("validation_not_passed", "fail", validation_missing, "Automation actions without successful validation evidence"),
        _guardrail("forbidden_path", "fail", forbidden_path, "Automation actions touching forbidden paths"),
        _guardrail("tier_blocked", "warn", tier_blocked, "Automation actions blocked by tier policy"),
        _guardrail("audit_missing", "warn", audit_missing, "Automation actions without audit log evidence"),
    ]


def auto_merge_policy_violation_items(db: Session) -> list[dict]:
    items = []
    for action, finding, application, repository in db.execute(_automation_context_stmt()):
        metadata = action.metadata_json or {}
        context = (action, finding, application, repository)
        merged = _is_merged_action(action)
        ci_passed = _metadata_bool_or_none(metadata.get("ci_passed"))
        validation_status = _validation_status(metadata)
        auto_merge_allowed = _metadata_bool_or_none(metadata.get("auto_merge_allowed"))
        if merged and auto_merge_allowed is False:
            items.append(_policy_violation("policy_disallowed_merged", *context, detail="Action merged despite auto_merge_allowed=false"))
        if merged and ci_passed is False:
            items.append(_policy_violation("ci_failed_merged", *context, detail="Action merged despite failed CI"))
        if merged and validation_status != "succeeded":
            items.append(_policy_violation("validation_missing_merged", *context, detail="Action merged without successful validation"))
        if _metadata_bool(metadata.get("auto_processed")) and (application.production or application.criticality in {"high", "critical"}):
            items.append(_policy_violation("production_high_automated", *context, detail="Automation processed production or high criticality application"))
        if _metadata_bool(metadata.get("touches_forbidden_path")):
            items.append(_policy_violation("forbidden_path", *context, detail="Automation touched forbidden path"))
    return items


def auto_merge_dry_run_items(db: Session) -> list[dict]:
    items = []
    for action, finding, application, repository in db.execute(_automation_context_stmt()):
        metadata = action.metadata_json or {}
        if "dry_run" not in metadata and "dry_run_decision" not in metadata:
            continue
        raw_decision = str(metadata.get("dry_run_decision") or "")
        auto_merge_allowed = _metadata_bool_or_none(metadata.get("auto_merge_allowed"))
        decision = raw_decision or ("allowed" if auto_merge_allowed else "blocked")
        merged = _is_merged_action(action)
        mismatch = (decision in {"blocked", "denied", "not_allowed"} and merged) or (decision in {"allowed", "eligible"} and action.status in {"blocked", "failed"})
        items.append(
            schemas.AutoMergeDryRunOut(
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
                decision=decision,
                mismatch=mismatch,
                auto_merge_allowed=auto_merge_allowed,
                policy_reason=metadata.get("policy_reason"),
                ci_passed=_metadata_bool_or_none(metadata.get("ci_passed")),
                validation_status=_validation_status(metadata),
                detail=metadata.get("policy_reason") or metadata.get("dry_run_reason") or "Dry-run decision recorded",
                updated_at=action.updated_at,
            ).model_dump(mode="json")
        )
    return items


def _automation_context_stmt():
    return (
        select(models.RemediationAction, models.Finding, models.Application, models.Repository)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())
    )


def _guardrail(check: str, nonzero_status: str, count: int, detail: str) -> schemas.AutomationGuardrailOut:
    return schemas.AutomationGuardrailOut(
        check=check,
        status=nonzero_status if count else "ok",
        count=count,
        detail=detail,
    )


def _policy_violation(
    violation_type: str,
    action: models.RemediationAction,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    detail: str,
) -> dict:
    metadata = action.metadata_json or {}
    return schemas.AutoMergePolicyViolationOut(
        violation_type=violation_type,
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
        ci_passed=_metadata_bool_or_none(metadata.get("ci_passed")),
        validation_status=_validation_status(metadata),
        auto_merge_allowed=_metadata_bool_or_none(metadata.get("auto_merge_allowed")),
        detail=detail,
        updated_at=action.updated_at,
    ).model_dump(mode="json")


def _metadata_bool_or_none(value: object) -> bool | None:
    if value is None:
        return None
    return _metadata_bool(value)


def _validation_status(metadata: dict) -> str | None:
    value = metadata.get("validation_status") or metadata.get("validation_scan_status")
    return str(value) if value is not None else None


def _is_merged_action(action: models.RemediationAction) -> bool:
    metadata = action.metadata_json or {}
    return action.status in {"merged", "succeeded", "closed"} or bool(metadata.get("merged_at"))


def _has_audit_log(audit_logs: list[models.AuditLog], resource_type: str, resource_id: str) -> bool:
    return any(log.resource_type == resource_type and log.resource_id == resource_id for log in audit_logs)


def _metadata_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _tier_allows(application: models.Application, metadata: dict) -> bool:
    if "tier_allows" in metadata:
        return _metadata_bool(metadata["tier_allows"])
    return not application.production and application.criticality in {"low", "medium"}


def _pilot_reason(
    application: models.Application,
    decision_reason: str,
    ci_passed: bool,
    validation_scan_resolved: bool,
    tier_allows: bool,
    touches_forbidden_path: bool,
) -> str:
    if application.production or application.criticality in {"high", "critical"}:
        return "production_or_high_criticality"
    if not application.auto_merge_enabled:
        return "auto_merge_disabled"
    if not ci_passed:
        return "ci_failed"
    if not validation_scan_resolved:
        return "missing_validation"
    if not tier_allows:
        return "tier_blocked"
    if touches_forbidden_path:
        return "forbidden_path"
    return "eligible" if decision_reason == "eligible" else decision_reason
