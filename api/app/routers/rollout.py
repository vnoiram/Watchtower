from datetime import datetime, timedelta, timezone
from uuid import UUID

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


@router.get("/baseline", response_model=list[schemas.RolloutBaselineOut])
def rollout_baseline(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return rollout_baseline_items(db)


@router.get("/application-readiness", response_model=schemas.CursorPage)
def list_application_readiness(
    limit: int = 50,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = application_readiness_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/repository-drift", response_model=schemas.CursorPage)
def list_repository_drift(
    limit: int = 50,
    issue_type: str | None = None,
    provider: models.RepositoryProvider | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = repository_drift_items(db)
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    if provider:
        items = [item for item in items if item["provider"] == provider.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/waves", response_model=list[schemas.RolloutWaveOut])
def rollout_waves(
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    return rollout_wave_items(db)


@router.get("/mvp-targets", response_model=schemas.CursorPage)
def list_mvp_target_readiness(
    limit: int = 50,
    ready: bool | None = None,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = mvp_target_readiness_items(db)
    if ready is not None:
        items = [item for item in items if item["ready"] is ready]
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/initial-inventory", response_model=schemas.CursorPage)
def list_initial_inventory(
    limit: int = 50,
    complete: bool | None = None,
    issue_type: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = initial_inventory_items(db)
    if complete is not None:
        items = [item for item in items if item["complete"] is complete]
    if issue_type:
        items = [item for item in items if item["issue_type"] == issue_type]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/repository-inventory-gaps", response_model=schemas.CursorPage)
def list_repository_inventory_gaps(
    limit: int = 50,
    gap_type: str | None = None,
    provider: models.RepositoryProvider | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = repository_inventory_gap_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if provider:
        items = [item for item in items if item["provider"] == provider.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/onboarding-proof", response_model=schemas.CursorPage)
def list_repository_onboarding_proof(
    limit: int = 50,
    ready: bool | None = None,
    provider: models.RepositoryProvider | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = repository_onboarding_proof_items(db)
    if ready is not None:
        items = [item for item in items if item["ready"] is ready]
    if provider:
        items = [item for item in items if item["provider"] == provider.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


def rollout_gap_count(db: Session) -> int:
    return len(rollout_gap_items(db))


def application_readiness_count(db: Session) -> int:
    return len(application_readiness_items(db))


def rollout_wave_gap_count(db: Session) -> int:
    return sum(item.gap_count for item in rollout_wave_items(db))


def repository_inventory_gap_count(db: Session) -> int:
    return sum(item["count"] for item in repository_inventory_gap_items(db))


def repository_onboarding_gap_count(db: Session) -> int:
    return sum(1 for item in repository_onboarding_proof_items(db) if not item["ready"])


def rollout_baseline_items(db: Session) -> list[schemas.RolloutBaselineOut]:
    repositories = list(db.scalars(select(models.Repository)))
    total = len(repositories)
    visibility_known = sum(1 for repo in repositories if repo.visibility)
    classification_known = sum(1 for repo in repositories if repo.source_classification)
    archived = sum(1 for repo in repositories if repo.archived)
    forks = sum(1 for repo in repositories if repo.fork)
    active = total - archived
    return [
        _baseline("repository_inventory", total >= 54, total, 54, _percent(total, 54), "Registered repositories"),
        _baseline("visibility_known", visibility_known == total, total - visibility_known, 0, _percent(visibility_known, total), "Repositories without visibility"),
        _baseline("classification_known", classification_known == total, total - classification_known, 0, _percent(classification_known, total), "Repositories without source classification"),
        _baseline("archived_repositories", True, archived, None, _percent(archived, total), "Archived repositories in inventory"),
        _baseline("fork_repositories", True, forks, None, _percent(forks, total), "Fork repositories in inventory"),
        _baseline("active_repositories", True, active, None, _percent(active, total), "Non-archived repositories in inventory"),
    ]


def repository_inventory_gap_items(db: Session) -> list[dict]:
    repositories = _repositories_for_rollout(db)
    items = []
    if len(repositories) < 54:
        items.append(
            schemas.RepositoryInventoryGapOut(
                gap_type="repository_registration",
                count=54 - len(repositories),
                target=54,
                detail="Registered repository count is below the target of 54",
            ).model_dump(mode="json")
        )
    mvp_targets = _mvp_target_repositories(db)
    if len(mvp_targets) < 10:
        items.append(
            schemas.RepositoryInventoryGapOut(
                gap_type="mvp_target_selection",
                count=10 - len(mvp_targets),
                target=10,
                detail="MVP target repository selection is below 10",
            ).model_dump(mode="json")
        )
    for repository in repositories:
        context = {
            "repository_id": repository.id,
            "repository_owner": repository.owner,
            "repository_name": repository.name,
            "provider": repository.provider,
            "visibility": repository.visibility,
            "source_classification": repository.source_classification,
        }
        if not repository.visibility:
            items.append(_inventory_gap("missing_visibility", context, "Repository visibility is missing"))
        if repository.source_classification is None:
            items.append(_inventory_gap("missing_source_classification", context, "Repository source classification is missing"))
        if not repository.default_branch:
            items.append(_inventory_gap("missing_default_branch", context, "Repository default branch is missing"))
        if not repository.primary_language:
            items.append(_inventory_gap("missing_primary_language", context, "Repository primary language is missing"))
    return items


def repository_onboarding_proof_items(db: Session) -> list[dict]:
    items = []
    repositories = _repositories_for_rollout(db)
    for repository in repositories:
        applications = list(db.scalars(select(models.Application).where(models.Application.repository_id == repository.id)))
        application_ids = [application.id for application in applications]
        active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
        scans = _repository_scans(db, repository.id)
        latest_scan = scans[0] if scans else None
        open_count = _open_critical_high_count(db, application_ids)
        missing = []
        if not repository.visibility:
            missing.append("visibility")
        if not repository.default_branch:
            missing.append("default_branch")
        if not repository.primary_language:
            missing.append("primary_language")
        if not repository.topics:
            missing.append("topics")
        if not applications:
            missing.append("applications")
        if applications and len(active_sbom_app_ids) < len(applications):
            missing.append("active_source_sbom")
        if latest_scan is None:
            missing.append("latest_scan")
        if open_count:
            missing.append("critical_high_triage")
        ready = not missing
        items.append(
            schemas.RepositoryOnboardingProofOut(
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                provider=repository.provider,
                ready=ready,
                visibility=repository.visibility,
                default_branch=repository.default_branch,
                primary_language=repository.primary_language,
                topic_count=len(repository.topics or []),
                application_count=len(applications),
                active_source_sbom_count=len(active_sbom_app_ids),
                latest_scan_status=latest_scan.status if latest_scan else None,
                latest_scan_created_at=latest_scan.created_at if latest_scan else None,
                open_critical_high_count=open_count,
                missing_checks=missing,
                detail="Repository onboarding proof is complete" if ready else f"Missing {', '.join(missing)}",
            ).model_dump(mode="json")
        )
    return items


def application_readiness_items(db: Session) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .where(models.Application.lifecycle != models.Lifecycle.archived)
            .order_by(models.Repository.owner.asc(), models.Repository.name.asc(), models.Application.name.asc())
        )
    )
    application_ids = [application.id for application, _ in rows]
    active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
    scans = []
    for application, repository in rows:
        scans.extend(_repository_scans(db, repository.id))
    latest_scan_by_app = _latest_scan_by_application(scans)
    items = []
    for application, repository in rows:
        latest_scan = latest_scan_by_app.get(application.id)
        has_sbom = application.id in active_sbom_app_ids
        if not application.owner:
            items.append(_readiness_item("missing_owner", application, repository, latest_scan, has_sbom, "Active application has no owner"))
        if (application.criticality or "").lower() not in {"low", "medium", "high", "critical"}:
            items.append(_readiness_item("unknown_criticality", application, repository, latest_scan, has_sbom, "Application criticality is not classified"))
        if not has_sbom:
            items.append(_readiness_item("missing_active_source_sbom", application, repository, latest_scan, has_sbom, "Application has no active source SBOM"))
        if latest_scan is None or latest_scan.created_at < _matching_datetime(cutoff, latest_scan.created_at):
            items.append(_readiness_item("stale_scan", application, repository, latest_scan, has_sbom, "Application has no scan in the last 30 days"))
    return items


def repository_drift_items(db: Session) -> list[dict]:
    now = datetime.now(timezone.utc)
    sync_cutoff = now - timedelta(days=30)
    items = []
    repositories = list(
        db.scalars(select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc()))
    )
    for repository in repositories:
        applications = list(
            db.scalars(select(models.Application).where(models.Application.repository_id == repository.id))
        )
        active_apps = [app for app in applications if app.lifecycle != models.Lifecycle.archived]
        latest_scan = _repository_scans(db, repository.id)[0] if applications else None
        context = (repository, None, latest_scan)
        if repository.last_synced_at is None or _before(repository.last_synced_at, sync_cutoff):
            items.append(_drift_item("stale_sync", *context, count=1, detail="Repository has not synced in the last 30 days"))
        if not repository.visibility:
            items.append(_drift_item("missing_visibility", *context, count=1, detail="Repository visibility is missing"))
        if repository.source_classification is None:
            items.append(_drift_item("missing_classification", *context, count=1, detail="Repository source classification is missing"))
        if repository.pushed_at and latest_scan and repository.pushed_at > _matching_datetime(latest_scan.created_at, repository.pushed_at):
            items.append(_drift_item("pushed_after_scan", *context, count=1, detail="Repository has commits newer than latest scan"))
        if (repository.archived or repository.fork) and active_apps:
            for application in active_apps:
                items.append(
                    _drift_item(
                        "archived_or_fork_active_app",
                        repository,
                        application,
                        latest_scan,
                        count=1,
                        detail="Archived or fork repository still has active applications",
                    )
                )
    return items


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


def rollout_wave_items(db: Session) -> list[schemas.RolloutWaveOut]:
    repositories = _repositories_for_rollout(db)
    by_wave = _repositories_by_wave(repositories)
    items = []
    for wave in ["wave_1", "wave_2", "wave_3", "wave_4"]:
        repos = by_wave.get(wave, [])
        applications = _applications_for_repositories(db, repos)
        application_ids = [app.id for app in applications]
        active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
        scans = [scan for repo in repos for scan in _repository_scans(db, repo.id)]
        latest_scan_by_app = _latest_scan_by_application(scans)
        fresh_cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        fresh_apps = sum(
            1
            for app in applications
            if app.id in latest_scan_by_app
            and latest_scan_by_app[app.id].created_at >= _matching_datetime(
                fresh_cutoff, latest_scan_by_app[app.id].created_at
            )
        )
        owner_count = sum(1 for app in applications if app.owner)
        open_count = _open_critical_high_count(db, application_ids)
        gap_count = (
            sum(1 for repo in repos if not repo.visibility)
            + (len(applications) - owner_count)
            + max(len(applications) - len(active_sbom_app_ids), 0)
            + max(len(applications) - fresh_apps, 0)
            + open_count
        )
        items.append(
            schemas.RolloutWaveOut(
                wave=wave,
                repository_count=len(repos),
                application_count=len(applications),
                owner_completeness_percent=_percent(owner_count, len(applications)),
                active_sbom_coverage_percent=_percent(len(active_sbom_app_ids), len(applications)),
                fresh_scan_percent=_percent(fresh_apps, len(applications)),
                open_critical_high_count=open_count,
                gap_count=gap_count,
                detail="Rollout wave readiness from repository inventory, app ownership, SBOM, scans, and open critical/high findings",
            )
        )
    return items


def mvp_target_readiness_items(db: Session) -> list[dict]:
    repositories = _mvp_target_repositories(db)
    items = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    for repository in repositories:
        applications = list(db.scalars(select(models.Application).where(models.Application.repository_id == repository.id)))
        application_ids = [app.id for app in applications]
        active_sbom_app_ids = _active_sbom_application_ids(db, application_ids)
        scans = _repository_scans(db, repository.id)
        latest_scan = scans[0] if scans else None
        open_count = _open_critical_high_count(db, application_ids)
        owner_count = sum(1 for app in applications if app.owner)
        checks = {
            "missing_visibility": bool(repository.visibility),
            "missing_application": bool(applications),
            "missing_owner": bool(applications) and owner_count == len(applications),
            "missing_active_source_sbom": bool(applications) and len(active_sbom_app_ids) == len(applications),
            "stale_scan": latest_scan is not None and latest_scan.created_at >= _matching_datetime(cutoff, latest_scan.created_at),
            "open_critical_high": open_count == 0,
        }
        failing = [issue for issue, ok in checks.items() if not ok]
        issue_type = "ready" if not failing else failing[0]
        items.append(
            schemas.MvpTargetReadinessOut(
                issue_type=issue_type,
                ready=not failing,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                application_count=len(applications),
                owner_completeness_percent=_percent(owner_count, len(applications)),
                active_sbom_coverage_percent=_percent(len(active_sbom_app_ids), len(applications)),
                latest_scan_created_at=latest_scan.created_at if latest_scan else None,
                open_critical_high_count=open_count,
                detail="MVP target is ready" if not failing else f"MVP target has {', '.join(failing)}",
            ).model_dump(mode="json")
        )
    return items


def initial_inventory_items(db: Session) -> list[dict]:
    items = []
    notification_finding_ids = _notified_finding_ids(db)
    action_finding_ids = _action_finding_ids(db)
    exception_finding_ids = _exception_finding_ids(db)
    repositories = _repositories_for_rollout(db)
    for repository in repositories:
        applications = list(db.scalars(select(models.Application).where(models.Application.repository_id == repository.id)))
        if not applications:
            items.append(_initial_inventory_item("missing_application", False, repository, None, None, 0, False, False, "Repository has no detected applications"))
            continue
        for application in applications:
            scans = list(
                db.scalars(
                    select(models.Scan)
                    .where(models.Scan.application_id == application.id)
                    .order_by(models.Scan.created_at.desc(), models.Scan.id.desc())
                )
            )
            latest_scan = scans[0] if scans else None
            findings = list(
                db.scalars(
                    select(models.Finding).where(
                        models.Finding.application_id == application.id,
                        models.Finding.severity.in_([models.Severity.critical, models.Severity.high]),
                    )
                )
            )
            open_findings = [finding for finding in findings if finding.status == models.FindingStatus.open]
            has_notification_or_action = any(
                finding.id in notification_finding_ids or finding.id in action_finding_ids for finding in findings
            )
            has_exception = any(finding.id in exception_finding_ids for finding in findings)
            complete = latest_scan is not None and (not open_findings or has_notification_or_action or has_exception)
            if latest_scan is None:
                issue_type = "missing_scan"
                detail = "Application has no initial scan"
            elif open_findings and not has_notification_or_action and not has_exception:
                issue_type = "missing_triage_evidence"
                detail = "Open critical/high findings have no notification, issue/PR, or exception evidence"
            else:
                issue_type = "complete"
                detail = "Initial critical/high inventory is complete"
            items.append(
                _initial_inventory_item(
                    issue_type,
                    complete,
                    repository,
                    application,
                    latest_scan,
                    len(open_findings),
                    has_notification_or_action,
                    has_exception,
                    detail,
                )
            )
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


def _repositories_for_rollout(db: Session) -> list[models.Repository]:
    return list(db.scalars(select(models.Repository).order_by(models.Repository.owner.asc(), models.Repository.name.asc())))


def _applications_for_repositories(db: Session, repositories: list[models.Repository]) -> list[models.Application]:
    repository_ids = [repo.id for repo in repositories]
    if not repository_ids:
        return []
    return list(db.scalars(select(models.Application).where(models.Application.repository_id.in_(repository_ids))))


def _repositories_by_wave(repositories: list[models.Repository]) -> dict[str, list[models.Repository]]:
    by_wave = {f"wave_{index}": [] for index in range(1, 5)}
    unassigned = []
    for repository in repositories:
        wave = _explicit_wave(repository)
        if wave:
            by_wave[wave].append(repository)
        else:
            unassigned.append(repository)
    fallback_sizes = [10, 15, 15, 14]
    cursor = 0
    for index, size in enumerate(fallback_sizes, start=1):
        wave = f"wave_{index}"
        remaining = max(size - len(by_wave[wave]), 0)
        if remaining:
            by_wave[wave].extend(unassigned[cursor : cursor + remaining])
            cursor += remaining
    if cursor < len(unassigned):
        by_wave["wave_4"].extend(unassigned[cursor:])
    return by_wave


def _explicit_wave(repository: models.Repository) -> str | None:
    for topic in repository.topics or []:
        normalized = str(topic).lower().replace("_", "-")
        for index in range(1, 5):
            if normalized in {f"wave-{index}", f"rollout-wave-{index}"}:
                return f"wave_{index}"
    return None


def _mvp_target_repositories(db: Session) -> list[models.Repository]:
    repositories = _repositories_for_rollout(db)
    explicit = [
        repo
        for repo in repositories
        if {str(topic).lower() for topic in (repo.topics or [])} & {"mvp", "mvp-target", "wave-1", "wave_1"}
    ]
    if explicit:
        return explicit[:10]
    return [repo for repo in repositories if not repo.archived][:10]


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


def _notified_finding_ids(db: Session) -> set:
    finding_ids = set()
    for notification in db.scalars(select(models.Notification).where(models.Notification.status == "sent")):
        finding_id = (notification.metadata_json or {}).get("finding_id")
        if not finding_id:
            continue
        try:
            finding_ids.add(UUID(str(finding_id)))
        except ValueError:
            continue
    return finding_ids


def _action_finding_ids(db: Session) -> set:
    return {action.finding_id for action in db.scalars(select(models.RemediationAction)) if action.action_type or action.url or action.branch}


def _exception_finding_ids(db: Session) -> set:
    vex_ids = set(db.scalars(select(models.VexStatement.finding_id)))
    exception_ids = set(
        db.scalars(
            select(models.Finding.id).where(
                models.Finding.status.in_([models.FindingStatus.accepted_risk, models.FindingStatus.false_positive])
            )
        )
    )
    return vex_ids | exception_ids


def _initial_inventory_item(
    issue_type: str,
    complete: bool,
    repository: models.Repository,
    application: models.Application | None,
    latest_scan: models.Scan | None,
    open_critical_high_count: int,
    has_notification_or_action: bool,
    has_exception: bool,
    detail: str,
) -> dict:
    return schemas.InitialInventoryOut(
        issue_type=issue_type,
        complete=complete,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        open_critical_high_count=open_critical_high_count,
        has_notification_or_action=has_notification_or_action,
        has_exception=has_exception,
        detail=detail,
    ).model_dump(mode="json")


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


def _baseline(
    check: str,
    ok: bool,
    count: int,
    target: int | None,
    percent: float | None,
    detail: str,
) -> schemas.RolloutBaselineOut:
    return schemas.RolloutBaselineOut(
        check=check,
        status="ok" if ok else "warn",
        count=count,
        target=target,
        percent=percent,
        detail=detail,
    )


def _inventory_gap(gap_type: str, context: dict, detail: str) -> dict:
    return schemas.RepositoryInventoryGapOut(
        gap_type=gap_type,
        repository_id=context["repository_id"],
        repository_owner=context["repository_owner"],
        repository_name=context["repository_name"],
        provider=context["provider"],
        visibility=context["visibility"],
        source_classification=context["source_classification"],
        count=1,
        detail=detail,
    ).model_dump(mode="json")


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


def _readiness_item(
    issue_type: str,
    application: models.Application,
    repository: models.Repository,
    latest_scan: models.Scan | None,
    has_active_source_sbom: bool,
    detail: str,
) -> dict:
    return schemas.ApplicationReadinessOut(
        issue_type=issue_type,
        application_id=application.id,
        application_name=application.name,
        application_path=application.path,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        owner=application.owner,
        criticality=application.criticality,
        lifecycle=application.lifecycle,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_status=latest_scan.status if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        has_active_source_sbom=has_active_source_sbom,
        detail=detail,
    ).model_dump(mode="json")


def _drift_item(
    issue_type: str,
    repository: models.Repository,
    application: models.Application | None,
    latest_scan: models.Scan | None,
    count: int,
    detail: str,
) -> dict:
    return schemas.RepositoryDriftOut(
        issue_type=issue_type,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        provider=repository.provider,
        source_classification=repository.source_classification,
        application_id=application.id if application else None,
        application_name=application.name if application else None,
        latest_scan_id=latest_scan.id if latest_scan else None,
        latest_scan_created_at=latest_scan.created_at if latest_scan else None,
        count=count,
        detail=detail,
    ).model_dump(mode="json")


def _before(value: datetime, reference: datetime) -> bool:
    if value.tzinfo is None:
        reference = reference.replace(tzinfo=None)
    elif reference.tzinfo is None:
        value = value.replace(tzinfo=None)
    return value < reference
