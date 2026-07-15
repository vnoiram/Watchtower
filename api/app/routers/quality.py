from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/quality", tags=["quality"])

OPEN_ACTION_STATUSES = {
    "queued",
    "pending",
    "pending_provider",
    "created",
    "running",
    "in_progress",
    "close_failed",
}


@router.get("/duplicates", response_model=schemas.CursorPage)
def list_duplicate_review(
    limit: int = 50,
    duplicate_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = duplicate_review_items(db)
    if duplicate_type:
        items = [item for item in items if item["duplicate_type"] == duplicate_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/reopen-risk", response_model=schemas.CursorPage)
def list_reopen_risk(
    limit: int = 50,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = reopen_risk_items(db)
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/false-positive-review", response_model=schemas.CursorPage)
def list_false_positive_review(
    limit: int = 50,
    review_type: str | None = None,
    expired: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = false_positive_review_items(db)
    if review_type:
        items = [item for item in items if item["review_type"] == review_type]
    if expired is not None:
        items = [item for item in items if item["expired"] is expired]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def reopen_risk_count(db: Session) -> int:
    return len(reopen_risk_items(db))


def false_positive_review_count(db: Session) -> int:
    return len(false_positive_review_items(db))


def duplicate_review_items(db: Session) -> list[dict]:
    items = []
    items.extend(_notification_duplicates(db))
    items.extend(_remediation_duplicates(db))
    items.extend(_skipped_duplicate_actions(db))
    return sorted(items, key=lambda item: (item["duplicate_type"], item["key"])) 


def reopen_risk_items(db: Session) -> list[dict]:
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
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        scan = db.get(models.Scan, finding.last_seen_scan_id) if finding.last_seen_scan_id else None
        reason = None
        if finding.resolved_at and scan and _after(scan.created_at, finding.resolved_at):
            reason = "seen_after_resolved"
        elif _has_open_same_identity(db, finding):
            reason = "open_same_identity"
        if not reason:
            continue
        items.append(
            schemas.ReopenRiskOut(
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
                resolved_at=finding.resolved_at,
                last_seen_scan_id=scan.id if scan else None,
                last_seen_scan_created_at=scan.created_at if scan else None,
                reason=reason,
            ).model_dump(mode="json")
        )
    return items


def false_positive_review_items(db: Session) -> list[dict]:
    now = datetime.now()
    reopened_ids = {UUID(item["finding_id"]) for item in reopen_risk_items(db)}
    items = []
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.Finding.status == models.FindingStatus.false_positive)
        .order_by(models.Finding.updated_at.asc(), models.Finding.id.asc())
    )
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        reappeared = finding.id in reopened_ids
        items.append(
            _false_positive_item(
                "finding_false_positive",
                "finding",
                finding,
                application,
                repository,
                component,
                vulnerability,
                None,
                None,
                False,
                reappeared,
                "False positive finding requires periodic review",
            )
        )
    vex_stmt = (
        select(models.VexStatement, models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Finding, models.VexStatement.finding_id == models.Finding.id)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .where(models.VexStatement.status == models.VexStatus.not_affected)
        .order_by(models.VexStatement.review_date.asc(), models.VexStatement.id.asc())
    )
    for vex, finding, application, repository, component, vulnerability in db.execute(vex_stmt):
        expired = _before(vex.review_date, now)
        reappeared = finding.id in reopened_ids
        review_type = "expired_not_affected_vex" if expired else "not_affected_vex"
        items.append(
            _false_positive_item(
                review_type,
                "vex",
                finding,
                application,
                repository,
                component,
                vulnerability,
                vex.id,
                vex.review_date,
                expired,
                reappeared,
                "VEX not_affected statement requires review",
            )
        )
    return items


def _notification_duplicates(db: Session) -> list[dict]:
    groups: dict[tuple[str, str, str], list[models.Notification]] = {}
    for notification in db.scalars(select(models.Notification)):
        finding_id = str((notification.metadata_json or {}).get("finding_id") or "")
        if not finding_id:
            continue
        key = (finding_id, notification.channel, notification.subject)
        groups.setdefault(key, []).append(notification)

    items = []
    for (finding_id, channel, subject), notifications in groups.items():
        if len(notifications) < 2:
            continue
        finding = _get_finding(db, finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="notification",
                key=f"{finding_id}:{channel}:{subject}",
                count=len(notifications),
                finding_id=finding.id if finding else None,
                channel=channel,
                subject=subject,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Multiple notifications share finding, channel, and subject",
            ).model_dump(mode="json")
        )
    return items


def _remediation_duplicates(db: Session) -> list[dict]:
    groups: dict[tuple[UUID, str], list[models.RemediationAction]] = {}
    stmt = select(models.RemediationAction).where(models.RemediationAction.status.in_(OPEN_ACTION_STATUSES))
    for action in db.scalars(stmt):
        key = (action.finding_id, action.action_type)
        groups.setdefault(key, []).append(action)

    items = []
    for (finding_id, action_type), actions in groups.items():
        if len(actions) < 2:
            continue
        finding = db.get(models.Finding, finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="remediation_action",
                key=f"{finding_id}:{action_type}",
                count=len(actions),
                finding_id=finding_id,
                action_type=action_type,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Multiple open remediation actions share finding and action type",
            ).model_dump(mode="json")
        )
    return items


def _skipped_duplicate_actions(db: Session) -> list[dict]:
    items = []
    stmt = select(models.RemediationAction).where(models.RemediationAction.status == "skipped_duplicate")
    for action in db.scalars(stmt):
        finding = db.get(models.Finding, action.finding_id)
        application, repository = _finding_application_repository(db, finding)
        items.append(
            schemas.DuplicateReviewOut(
                duplicate_type="skipped_duplicate",
                key=f"{action.finding_id}:{action.action_type}:{action.id}",
                count=1,
                finding_id=action.finding_id,
                action_type=action.action_type,
                application_id=application.id if application else None,
                application_name=application.name if application else None,
                repository_id=repository.id if repository else None,
                repository_owner=repository.owner if repository else None,
                repository_name=repository.name if repository else None,
                detail="Duplicate prevention skipped a remediation action",
            ).model_dump(mode="json")
        )
    return items


def _get_finding(db: Session, finding_id: str) -> models.Finding | None:
    try:
        return db.get(models.Finding, UUID(str(finding_id)))
    except ValueError:
        return None


def _finding_application_repository(
    db: Session, finding: models.Finding | None
) -> tuple[models.Application | None, models.Repository | None]:
    if not finding:
        return None, None
    application = db.get(models.Application, finding.application_id)
    repository = db.get(models.Repository, application.repository_id) if application else None
    return application, repository


def _has_open_same_identity(db: Session, finding: models.Finding) -> bool:
    return bool(
        db.scalar(
            select(models.Finding.id)
            .where(
                models.Finding.id != finding.id,
                models.Finding.application_id == finding.application_id,
                models.Finding.component_id == finding.component_id,
                models.Finding.vulnerability_id == finding.vulnerability_id,
                models.Finding.status.in_(
                    [
                        models.FindingStatus.open,
                        models.FindingStatus.triaged,
                        models.FindingStatus.in_progress,
                    ]
                ),
            )
            .limit(1)
        )
    )


def _after(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value > reference


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None and reference.tzinfo is not None:
        reference = reference.replace(tzinfo=None)
    elif value.tzinfo is not None and reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference


def _false_positive_item(
    review_type: str,
    source: str,
    finding: models.Finding,
    application: models.Application,
    repository: models.Repository,
    component: models.Component,
    vulnerability: models.Vulnerability,
    vex_id: UUID | None,
    review_date: datetime | None,
    expired: bool,
    reappeared: bool,
    detail: str,
) -> dict:
    return schemas.FalsePositiveReviewOut(
        review_type=review_type,
        source=source,
        finding_id=finding.id,
        status=finding.status,
        severity=finding.severity,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        component_name=component.name,
        vulnerability_external_id=vulnerability.external_id,
        vex_id=vex_id,
        review_date=review_date,
        expired=expired,
        reappeared=reappeared,
        detail=detail,
    ).model_dump(mode="json")
