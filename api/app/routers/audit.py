from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/audit", tags=["audit"])

PRIVILEGED_ACTIONS = {
    "application.create",
    "backup.restore",
    "backup.restore.verify",
    "job.create",
    "repository.create",
    "repository.scan.enqueue",
    "restore.verify",
    "scan.create",
    "vex.create",
}


@router.get("/review", response_model=schemas.CursorPage)
def list_audit_review(
    limit: int = 50,
    reason: str | None = None,
    actor: str | None = None,
    role: str | None = None,
    resource_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = audit_review_items(db)
    if reason:
        items = [item for item in items if item["reason"] == reason]
    if actor:
        items = [item for item in items if item["actor"] == actor]
    if role:
        items = [item for item in items if item["role"] == role]
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/evidence-gaps", response_model=schemas.CursorPage)
def list_audit_evidence_gaps(
    limit: int = 50,
    resource_type: str | None = None,
    gap_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = audit_evidence_gap_items(db)
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/action-coverage", response_model=schemas.CursorPage)
def list_audit_action_coverage(
    limit: int = 50,
    resource_type: str | None = None,
    gap_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = audit_action_coverage_items(db)
    if resource_type:
        items = [item for item in items if item["resource_type"] == resource_type]
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def audit_action_gap_count(db: Session) -> int:
    return len(audit_action_coverage_items(db))


def audit_review_items(db: Session) -> list[dict]:
    items = []
    stmt = select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())
    for audit_log in db.scalars(stmt):
        review_reason = _audit_review_reason(audit_log)
        if not review_reason:
            continue
        items.append(
            schemas.AuditReviewOut(
                id=audit_log.id,
                actor=audit_log.actor,
                role=audit_log.role,
                action=audit_log.action,
                resource_type=audit_log.resource_type,
                resource_id=audit_log.resource_id,
                reason=review_reason,
                metadata_json=audit_log.metadata_json or {},
                created_at=audit_log.created_at,
            ).model_dump(mode="json")
        )
    return items


def audit_action_coverage_items(db: Session) -> list[dict]:
    audit_logs = _audit_logs_by_resource(db)
    items = []
    for repository in db.scalars(select(models.Repository).order_by(models.Repository.created_at.desc(), models.Repository.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "repository", str(repository.id), "repository.create", "missing_create_audit", repository.created_at))
    for application in db.scalars(select(models.Application).order_by(models.Application.created_at.desc(), models.Application.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "application", str(application.id), "application.create", "missing_create_audit", application.created_at))
    for scan in db.scalars(select(models.Scan).order_by(models.Scan.created_at.desc(), models.Scan.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "scan", str(scan.id), "scan.create", "missing_create_audit", scan.created_at))
    for job in db.scalars(select(models.Job).order_by(models.Job.created_at.desc(), models.Job.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "job", str(job.id), "job.create", "missing_create_audit", job.created_at))
    for finding in db.scalars(
        select(models.Finding)
        .where(models.Finding.status.in_([models.FindingStatus.accepted_risk, models.FindingStatus.false_positive, models.FindingStatus.resolved]))
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    ):
        items.extend(_audit_action_gap_for_record(audit_logs, "finding", str(finding.id), "finding.review", "missing_review_audit", finding.updated_at))
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "remediation_action", str(action.id), "remediation.action", "missing_update_audit", action.created_at))
    for vex in db.scalars(select(models.VexStatement).order_by(models.VexStatement.created_at.desc(), models.VexStatement.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "vex", str(vex.id), "vex.create", "missing_review_audit", vex.created_at))
    for notification in db.scalars(select(models.Notification).order_by(models.Notification.created_at.desc(), models.Notification.id.asc())):
        items.extend(_audit_action_gap_for_record(audit_logs, "notification", str(notification.id), "notification.delivery", "missing_delivery_audit", notification.created_at))
    return items


def audit_evidence_gap_items(db: Session) -> list[dict]:
    audit_logs = _audit_logs_by_resource(db)
    items = []
    for vex in db.scalars(select(models.VexStatement).order_by(models.VexStatement.created_at.desc(), models.VexStatement.id.asc())):
        items.extend(_audit_gap_for_record(audit_logs, "vex", str(vex.id), "vex.create", vex.created_at))
    for finding in db.scalars(
        select(models.Finding)
        .where(models.Finding.status.in_([models.FindingStatus.accepted_risk, models.FindingStatus.false_positive]))
        .order_by(models.Finding.updated_at.desc(), models.Finding.id.asc())
    ):
        items.extend(_audit_gap_for_record(audit_logs, "finding", str(finding.id), "finding.review", finding.updated_at))
    for action in db.scalars(select(models.RemediationAction).order_by(models.RemediationAction.created_at.desc(), models.RemediationAction.id.asc())):
        items.extend(_audit_gap_for_record(audit_logs, "remediation_action", str(action.id), "remediation.action", action.created_at))
    for notification in db.scalars(
        select(models.Notification)
        .where(models.Notification.status == "failed")
        .order_by(models.Notification.created_at.desc(), models.Notification.id.asc())
    ):
        items.extend(_audit_gap_for_record(audit_logs, "notification", str(notification.id), "notification.delivery", notification.created_at))
    for scan in db.scalars(
        select(models.Scan)
        .where(models.Scan.trigger_type == models.TriggerType.manual)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    ):
        items.extend(_audit_gap_for_record(audit_logs, "scan", str(scan.id), "scan.create", scan.created_at))
    for job in db.scalars(select(models.Job).order_by(models.Job.created_at.desc(), models.Job.id.asc())):
        payload = job.payload or {}
        if payload.get("manual") or job.job_type in {models.JobType.repository_sync, models.JobType.scan}:
            items.extend(_audit_gap_for_record(audit_logs, "job", str(job.id), "job.create", job.created_at))
    return items


def _audit_logs_by_resource(db: Session) -> dict[tuple[str, str], list[models.AuditLog]]:
    logs: dict[tuple[str, str], list[models.AuditLog]] = {}
    for audit_log in db.scalars(select(models.AuditLog).order_by(models.AuditLog.created_at.desc(), models.AuditLog.id.asc())):
        if audit_log.resource_id is None:
            continue
        logs.setdefault((audit_log.resource_type, audit_log.resource_id), []).append(audit_log)
    return logs


def _audit_gap_for_record(
    audit_logs: dict[tuple[str, str], list[models.AuditLog]],
    resource_type: str,
    resource_id: str,
    expected_action: str,
    created_at,
) -> list[dict]:
    logs = audit_logs.get((resource_type, resource_id), [])
    if not logs:
        return [
            _audit_gap(
                "missing_audit_log",
                resource_type,
                resource_id,
                expected_action,
                None,
                None,
                "Expected audit log is missing",
                created_at,
            )
        ]
    primary = logs[0]
    if not primary.actor or not primary.resource_id or not (primary.metadata_json or {}):
        return [
            _audit_gap(
                "incomplete_audit_log",
                resource_type,
                resource_id,
                expected_action,
                primary.actor,
                primary.id,
                "Audit log is missing actor, resource id, or metadata",
                primary.created_at,
            )
        ]
    return []


def _audit_action_gap_for_record(
    audit_logs: dict[tuple[str, str], list[models.AuditLog]],
    resource_type: str,
    resource_id: str,
    expected_action: str,
    gap_type: str,
    created_at,
) -> list[dict]:
    logs = audit_logs.get((resource_type, resource_id), [])
    matching = next((log for log in logs if log.action == expected_action), None)
    if matching:
        return []
    primary = logs[0] if logs else None
    return [
        schemas.AuditActionCoverageOut(
            gap_type=gap_type,
            resource_type=resource_type,
            resource_id=resource_id,
            expected_action=expected_action,
            audit_log_id=primary.id if primary else None,
            actor=primary.actor if primary else None,
            detail="Expected audit action is missing",
            created_at=primary.created_at if primary else created_at,
        ).model_dump(mode="json")
    ]


def _audit_gap(
    gap_type: str,
    resource_type: str,
    resource_id: str,
    expected_action: str,
    actor: str | None,
    audit_log_id,
    detail: str,
    created_at,
) -> dict:
    return schemas.AuditEvidenceGapOut(
        gap_type=gap_type,
        resource_type=resource_type,
        resource_id=resource_id,
        expected_action=expected_action,
        actor=actor,
        audit_log_id=audit_log_id,
        detail=detail,
        created_at=created_at,
    ).model_dump(mode="json")


def _audit_review_reason(audit_log: models.AuditLog) -> str | None:
    metadata = audit_log.metadata_json or {}
    searchable = f"{audit_log.action} {metadata}".lower()
    if audit_log.role != "admin" and audit_log.action in PRIVILEGED_ACTIONS:
        return "privileged_non_admin"
    if "fail" in searchable or "error" in searchable:
        return "failure_event"
    if audit_log.action in {"scan.create", "job.create", "repository.scan.enqueue"}:
        return "manual_operation"
    if audit_log.action in {"repository.create", "application.create", "vex.create"}:
        return "configuration_change"
    if "manual" in searchable:
        return "manual_operation"
    return None
