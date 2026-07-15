from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/rollout", tags=["rollout"])


@router.get("/repositories", response_model=schemas.CursorPage)
def list_repository_rollout(
    limit: int = 50,
    provider: models.RepositoryProvider | None = None,
    source_classification: models.SourceClassification | None = None,
    archived: bool | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    stmt = select(models.Repository)
    if provider:
        stmt = stmt.where(models.Repository.provider == provider)
    if source_classification:
        stmt = stmt.where(models.Repository.source_classification == source_classification)
    if archived is not None:
        stmt = stmt.where(models.Repository.archived.is_(archived))
    stmt = stmt.order_by(models.Repository.owner.asc(), models.Repository.name.asc()).limit(min(limit, 100))

    items = []
    for repository in db.execute(stmt).scalars():
        applications = list(
            db.scalars(select(models.Application).where(models.Application.repository_id == repository.id))
        )
        scans = _repository_scans(db, repository.id)
        latest_scan = scans[0] if scans else None
        application_ids = [app.id for app in applications]
        active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
        stale_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        latest_scan_by_app = _latest_scan_by_application(scans)
        stale_scan_count = sum(
            1
            for app in applications
            if app.id not in latest_scan_by_app
            or latest_scan_by_app[app.id].created_at < _matching_datetime(
                stale_cutoff, latest_scan_by_app[app.id].created_at
            )
        )
        open_critical_high_count = _open_critical_high_count(db, application_ids)
        owner_count = sum(1 for app in applications if app.owner)

        items.append(
            schemas.RepositoryRolloutOut(
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                provider=repository.provider,
                source_classification=repository.source_classification,
                archived=repository.archived,
                application_count=len(applications),
                owner_completeness_percent=_percent(owner_count, len(applications)),
                active_sbom_coverage_percent=_percent(len(active_sbom_app_ids), len(applications)),
                latest_scan_status=latest_scan.status if latest_scan else None,
                latest_scan_created_at=latest_scan.created_at if latest_scan else None,
                stale_scan_count=stale_scan_count,
                open_critical_high_count=open_critical_high_count,
            ).model_dump(mode="json")
        )
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/gaps", response_model=schemas.CursorPage)
def list_rollout_gaps(
    limit: int = 50,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = rollout_gap_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def rollout_gap_count(db: Session) -> int:
    return len(rollout_gap_items(db))


def rollout_gap_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    repositories = list(
        db.scalars(select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc()))
    )
    items = []
    for repository in repositories:
        applications = list(
            db.scalars(select(models.Application).where(models.Application.repository_id == repository.id))
        )
        if not applications:
            items.append(
                schemas.RolloutGapOut(
                    issue_type="missing_application",
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                    count=1,
                    detail="Repository has no detected applications",
                ).model_dump(mode="json")
            )
            continue

        application_ids = [application.id for application in applications]
        active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
        latest_scan_by_app = _latest_scan_by_application(_repository_scans(db, repository.id))
        open_counts = _open_critical_high_counts_by_application(db, application_ids)
        for application in applications:
            if application.lifecycle == models.Lifecycle.archived:
                continue
            latest_scan = latest_scan_by_app.get(application.id)
            if not application.owner:
                items.append(_rollout_gap("missing_owner", repository, application, latest_scan, 1, "Active application has no owner"))
            if application.id not in active_sbom_app_ids:
                items.append(_rollout_gap("missing_active_source_sbom", repository, application, latest_scan, 1, "Active application has no active source SBOM"))
            if latest_scan is None or latest_scan.created_at < _matching_datetime(cutoff, latest_scan.created_at):
                items.append(_rollout_gap("stale_scan", repository, application, latest_scan, 1, "Application has no scan in the last 30 days"))
            open_count = open_counts.get(application.id, 0)
            if open_count:
                items.append(_rollout_gap("open_critical_high", repository, application, latest_scan, open_count, "Application has open critical or high findings"))
    return items


def _repository_scans(db: Session, repository_id) -> list[models.Scan]:
    return list(
        db.scalars(
            select(models.Scan)
            .join(models.Application, models.Scan.application_id == models.Application.id)
            .where(models.Application.repository_id == repository_id)
            .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
        )
    )


def _latest_scan_by_application(scans: list[models.Scan]) -> dict:
    latest = {}
    for scan in scans:
        latest.setdefault(scan.application_id, scan)
    return latest


def _open_critical_high_count(db: Session, application_ids: list) -> int:
    if not application_ids:
        return 0
    return (
        db.scalar(
            select(func.count())
            .select_from(models.Finding)
            .where(
                models.Finding.application_id.in_(application_ids),
                models.Finding.status == models.FindingStatus.open,
                models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
            )
        )
        or 0
    )


def _open_critical_high_counts_by_application(db: Session, application_ids: list) -> dict:
    counts = {}
    if not application_ids:
        return counts
    findings = db.scalars(
        select(models.Finding).where(
            models.Finding.application_id.in_(application_ids),
            models.Finding.status == models.FindingStatus.open,
            models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
        )
    )
    for finding in findings:
        counts[finding.application_id] = counts.get(finding.application_id, 0) + 1
    return counts


def _active_sbom_application_ids(db: Session, application_ids: list) -> set:
    if not application_ids:
        return set()
    return set(
        db.scalars(
            select(models.Sbom.application_id).where(
                models.Sbom.application_id.in_(application_ids),
                models.Sbom.active.is_(True),
                models.Sbom.sbom_kind == "source",
            )
        )
    )


def _percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator) * 100, 1) if denominator else 0.0


def _matching_datetime(reference: datetime, value: datetime) -> datetime:
    if value.tzinfo is None:
        return reference.replace(tzinfo=None)
    return reference


def _rollout_gap(
    issue_type: str,
    repository: models.Repository,
    application: models.Application,
    latest_scan: models.Scan | None,
    count: int,
    detail: str,
) -> dict:
    return schemas.RolloutGapOut(
        issue_type=issue_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        application_id=application.id,
        application_name=application.name,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_status=latest_scan.status if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        count=count,
        detail=detail,
    ).model_dump(mode="json")
