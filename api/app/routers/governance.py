import re
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal
from api.app.routers.scan_health import _latest_scans_by_application

router = APIRouter(prefix="/governance", tags=["governance"])

KNOWN_CRITICALITIES = {"low", "medium", "high", "critical"}


@router.get("/ownership", response_model=schemas.CursorPage)
def list_ownership_review(
    limit: int = 50,
    issue_type: str | None = None,
    repository_id: UUID | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = ownership_review_items(db, repository_id=repository_id)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/exposure", response_model=schemas.CursorPage)
def list_exposure_review(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return schemas.CursorPage(items=exposure_review_items(db)[: min(limit, 100)], next_cursor=None)


@router.get("/auto-merge-scope", response_model=schemas.CursorPage)
def list_auto_merge_scope(
    limit: int = 50,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return schemas.CursorPage(items=auto_merge_scope_items(db)[: min(limit, 100)], next_cursor=None)


@router.get("/runtime-eol", response_model=schemas.CursorPage)
def list_runtime_eol(
    limit: int = 50,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = runtime_eol_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def exposure_review_count(db: Session) -> int:
    return len(exposure_review_items(db))


def ownership_review_items(db: Session, repository_id: UUID | None = None) -> list[dict]:
    stmt = (
        select(models.Application, models.Repository)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
    )
    if repository_id:
        stmt = stmt.where(models.Repository.id == repository_id)
    items = []
    for application, repository in db.execute(stmt):
        for issue_type, detail in _ownership_issues(application):
            items.append(_ownership_item(issue_type, detail, application, repository))
    return items


def exposure_review_items(db: Session) -> list[dict]:
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where((models.Application.internet_exposed.is_(True)) | (models.Application.production.is_(True)))
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    latest_scans = _latest_scans_by_application(db, [application.id for application, _ in rows])
    sbom_app_ids = set(
        db.scalars(
            select(models.Sbom.application_id).where(
                models.Sbom.active.is_(True),
                models.Sbom.sbom_kind == "source",
            )
        )
    )
    open_counts = _open_critical_high_counts(db)
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    items = []
    for application, repository in rows:
        scan = latest_scans.get(application.id)
        reasons = []
        has_sbom = application.id in sbom_app_ids
        if not has_sbom:
            reasons.append("missing_active_source_sbom")
        if scan is None or _before(scan.created_at, cutoff):
            reasons.append("stale_scan")
        if scan is not None and scan.status in {models.ScanStatus.failed, models.ScanStatus.timed_out}:
            reasons.append("latest_scan_failed")
        open_count = open_counts.get(application.id, 0)
        if open_count:
            reasons.append("open_critical_high")
        if not reasons:
            continue
        items.append(
            schemas.ExposureReviewOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                internet_exposed=application.internet_exposed,
                production=application.production,
                latest_scan_id=scan.id if scan else None,
                latest_scan_status=scan.status if scan else None,
                latest_scan_created_at=scan.created_at if scan else None,
                open_critical_high_count=open_count,
                has_active_source_sbom=has_sbom,
                reasons=reasons,
            ).model_dump(mode="json")
        )
    return items


def auto_merge_scope_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(models.Application.auto_merge_enabled.is_(True))
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    validation_by_app = _recent_validation_by_application(db, cutoff)
    blocked_by_app = _blocked_auto_merge_actions_by_application(db)
    items = []
    for application, repository in rows:
        reasons = []
        criticality = (application.criticality or "").lower()
        if application.production:
            reasons.append("production")
        if criticality in {"high", "critical"}:
            reasons.append("high_criticality")
        if application.internet_exposed:
            reasons.append("internet_exposed")
        recent_validation = application.id in validation_by_app
        if not recent_validation:
            reasons.append("missing_recent_validation")
        blocked_count = blocked_by_app.get(application.id, 0)
        if blocked_count:
            reasons.append("blocked_auto_merge_action")
        items.append(
            schemas.AutoMergeScopeOut(
                application_id=application.id,
                application_name=application.name,
                application_path=application.path,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                auto_merge_enabled=application.auto_merge_enabled,
                production=application.production,
                criticality=application.criticality,
                internet_exposed=application.internet_exposed,
                recent_validation=recent_validation,
                blocked_action_count=blocked_count,
                reasons=reasons,
            ).model_dump(mode="json")
        )
    return items


def runtime_eol_items(db: Session) -> list[dict]:
    items = []
    rows = db.execute(
        select(models.Technology, models.Application, models.Repository)
        .join(models.Application, models.Technology.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Technology.name.asc(), models.Technology.id.asc())
    )
    for technology, application, repository in rows:
        if not _runtime_candidate(technology.name, technology.category):
            continue
        issue = _runtime_issue(technology.name, technology.version)
        if not issue:
            continue
        issue_type, detail = issue
        items.append(
            schemas.RuntimeEolOut(
                source="technology",
                source_id=technology.id,
                issue_type=issue_type,
                name=technology.name,
                version=technology.version,
                category=technology.category,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                detail=detail,
            ).model_dump(mode="json")
        )

    component_rows = db.execute(
        select(models.Component, models.Sbom, models.Application, models.Repository)
        .join(models.SbomComponent, models.Component.id == models.SbomComponent.component_id)
        .join(models.Sbom, models.SbomComponent.sbom_id == models.Sbom.id)
        .join(models.Application, models.Sbom.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .where(models.Sbom.active.is_(True))
        .order_by(models.Component.name.asc(), models.Component.id.asc())
    )
    seen_components: set[tuple] = set()
    for component, _, application, repository in component_rows:
        if not _runtime_candidate(component.name, component.ecosystem or ""):
            continue
        key = (component.id, application.id)
        if key in seen_components:
            continue
        seen_components.add(key)
        issue = _runtime_issue(component.name, component.version)
        if not issue:
            continue
        issue_type, detail = issue
        items.append(
            schemas.RuntimeEolOut(
                source="component",
                source_id=component.id,
                issue_type=issue_type,
                name=component.name,
                version=component.version,
                ecosystem=component.ecosystem,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                detail=detail,
            ).model_dump(mode="json")
        )
    return items


def _ownership_issues(application: models.Application) -> list[tuple[str, str]]:
    issues = []
    criticality = (application.criticality or "").lower()
    if not application.owner:
        issues.append(("missing_owner", "Application has no owner"))
    if criticality not in KNOWN_CRITICALITIES:
        issues.append(("unknown_criticality", "Application criticality is not classified"))
    if application.production and criticality == "low":
        issues.append(("production_low_criticality", "Production application is classified as low criticality"))
    if application.support_status != "supported":
        issues.append(("unsupported", "Application support status is not supported"))
    if application.lifecycle in {models.Lifecycle.deprecated, models.Lifecycle.archived}:
        issues.append((application.lifecycle.value, "Application lifecycle requires governance review"))
    return issues


def _runtime_candidate(name: str | None, category: str | None) -> bool:
    normalized_name = (name or "").lower()
    normalized_category = (category or "").lower()
    if any(token in normalized_category for token in ["runtime", "platform", "language", "container"]):
        return True
    return _runtime_key(normalized_name) is not None


def _runtime_issue(name: str | None, version: str | None) -> tuple[str, str] | None:
    key = _runtime_key((name or "").lower())
    if not version:
        return "missing_version", "Runtime or platform version is missing"
    if not key:
        return None
    major = _major_version(version)
    if major is None:
        return "unparseable_version", "Runtime or platform version could not be parsed"
    thresholds = {
        "python": 3,
        "node": 18,
        "java": 17,
        "ruby": 3,
        "php": 8,
        "dotnet": 6,
        "go": 1,
    }
    threshold = thresholds.get(key)
    if threshold is not None and major < threshold:
        return "old_major", f"{name} major version is below the maintenance review threshold"
    if key == "go":
        minor = _minor_version(version)
        if minor is not None and minor < 20:
            return "old_major", "Go 1.x minor version is below the maintenance review threshold"
    return None


def _runtime_key(value: str) -> str | None:
    normalized = value.lower().replace(".js", "").replace(" ", "")
    if normalized in {"python", "python3"}:
        return "python"
    if normalized in {"node", "nodejs", "node.js"}:
        return "node"
    if normalized in {"java", "jdk", "openjdk"}:
        return "java"
    if normalized == "go" or normalized == "golang":
        return "go"
    if normalized == "ruby":
        return "ruby"
    if normalized == "php":
        return "php"
    if normalized in {"dotnet", ".net", "aspnet"}:
        return "dotnet"
    return None


def _major_version(version: str) -> int | None:
    match = re.search(r"(\d+)", version)
    return int(match.group(1)) if match else None


def _minor_version(version: str) -> int | None:
    match = re.search(r"\d+\.(\d+)", version)
    return int(match.group(1)) if match else None


def _ownership_item(
    issue_type: str,
    detail: str,
    application: models.Application,
    repository: models.Repository,
) -> dict:
    return schemas.GovernanceOwnershipOut(
        issue_type=issue_type,
        application_id=application.id,
        application_name=application.name,
        application_path=application.path,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        owner=application.owner,
        criticality=application.criticality,
        production=application.production,
        lifecycle=application.lifecycle,
        support_status=application.support_status,
        detail=detail,
    ).model_dump(mode="json")


def _open_critical_high_counts(db: Session) -> dict:
    counts = {}
    findings = db.scalars(
        select(models.Finding).where(
            models.Finding.status == models.FindingStatus.open,
            models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
        )
    )
    for finding in findings:
        counts[finding.application_id] = counts.get(finding.application_id, 0) + 1
    return counts


def _recent_validation_by_application(db: Session, cutoff: datetime) -> set:
    application_ids = set()
    rows = (
        db.execute(
            select(models.RemediationAction, models.Finding)
            .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
            .where(models.RemediationAction.updated_at >= cutoff)
        )
    )
    for action, finding in rows:
        metadata = action.metadata_json or {}
        if metadata.get("validation_status") == "succeeded" or action.status in {"succeeded", "merged", "closed"}:
            application_ids.add(finding.application_id)
    return application_ids


def _blocked_auto_merge_actions_by_application(db: Session) -> dict:
    counts = {}
    rows = db.execute(
        select(models.RemediationAction, models.Finding)
        .join(models.Finding, models.RemediationAction.finding_id == models.Finding.id)
        .where(models.RemediationAction.action_type == "ai_fix")
    )
    for action, finding in rows:
        metadata = action.metadata_json or {}
        blocked = action.status in {"failed", "blocked"} or metadata.get("auto_merge_allowed") is False
        if blocked:
            counts[finding.application_id] = counts.get(finding.application_id, 0) + 1
    return counts


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
