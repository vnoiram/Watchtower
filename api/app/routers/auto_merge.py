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
