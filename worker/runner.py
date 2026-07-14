from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import get_settings
from api.app.database import SessionLocal
from api.app.models import (
    Application,
    ApplicationType,
    Finding,
    Job,
    JobType,
    Notification,
    RemediationAction,
    Repository,
    Scan,
    ScanStatus,
    Technology,
    TriggerType,
    now_utc,
)
from api.app.services.artifacts import ArtifactStore, artifact_key
from api.app.services.jobs import enqueue_job, lock_next_job, mark_job_failed, mark_job_succeeded
from api.app.services.notifications import deliver_notification, enqueue_finding_notifications
from api.app.services.registry import detect_applications
from api.app.services.remediation import (
    enqueue_github_issue_requests,
    process_github_issue_closures,
    process_github_issue_actions,
)
from api.app.services.repositories import sync_github_repositories
from api.app.services.scanner import normalize_osv_results, normalize_trivy_results
from api.app.services.sbom import upsert_source_sbom
from api.app.services.vulnerabilities import upsert_findings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("watchtower.worker")


def run_command(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def clone_repository(repo: Repository, destination: Path) -> Path:
    if repo.local_path:
        source = Path(repo.local_path)
        target = destination / repo.name
        shutil.copytree(source, target)
        return target
    if not repo.url:
        raise RuntimeError("repository has neither local_path nor url")
    target = destination / repo.name
    result = run_command(["git", "clone", "--depth", "1", repo.url, str(target)])
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")
    return target


def upsert_detected_applications(db: Session, repo: Repository, root: Path) -> list[Application]:
    apps: list[Application] = []
    for detected in detect_applications(root):
        app = (
            db.query(Application)
            .filter(Application.repository_id == repo.id, Application.path == detected["path"])
            .one_or_none()
        )
        if not app:
            app = Application(
                repository_id=repo.id,
                name=detected["name"],
                path=detected["path"],
                application_type=ApplicationType(detected["application_type"]),
            )
            db.add(app)
            db.flush()
        db.add(
            Technology(
                application_id=app.id,
                category="language-or-platform",
                name=detected["technology"],
                detection_source=detected["detection_source"],
            )
        )
        apps.append(app)
    return apps


def run_syft(target: Path, output_path: Path) -> dict:
    result = run_command(["syft", str(target), "-o", "cyclonedx-json"])
    if result.returncode != 0:
        raise RuntimeError(f"syft failed: {result.stderr.strip() or result.stdout.strip()}")
    if not result.stdout.strip():
        raise RuntimeError("syft produced empty output")
    output_path.write_text(result.stdout, encoding="utf-8")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"syft produced invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("syft output must be a JSON object")
    return payload


def run_json_scanner(tool: str, args: list[str], output_path: Path) -> dict:
    result = run_command(args)
    if result.returncode != 0:
        raise RuntimeError(f"{tool} failed: {result.stderr.strip() or result.stdout.strip()}")
    if not result.stdout.strip():
        raise RuntimeError(f"{tool} produced empty output")
    output_path.write_text(result.stdout, encoding="utf-8")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{tool} produced invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{tool} output must be a JSON object")
    return payload


def run_osv_scanner(target: Path, output_path: Path) -> dict:
    return run_json_scanner(
        "osv-scanner",
        ["osv-scanner", "--format", "json", "--recursive", str(target)],
        output_path,
    )


def run_trivy(target: Path, output_path: Path) -> dict:
    return run_json_scanner(
        "trivy",
        ["trivy", "fs", "--format", "json", str(target)],
        output_path,
    )


def scan_application(
    db: Session,
    repo: Repository,
    app: Application,
    root: Path,
    store: ArtifactStore,
    workdir: Path,
    *,
    trigger_type: TriggerType = TriggerType.manual,
) -> bool:
    started = now_utc()
    scan = Scan(
        application_id=app.id,
        trigger_type=trigger_type,
        status=ScanStatus.running,
        tool="syft",
        started_at=started,
    )
    db.add(scan)
    db.flush()

    try:
        target = root / app.path
        output_path = workdir / f"{scan.id}-source-sbom.cdx.json"
        payload = run_syft(target, output_path)
        key = artifact_key(str(repo.id), str(app.id), str(scan.id), "source-sbom.cdx.json")
        digest = store.put_file(key, output_path)
        _, component_count = upsert_source_sbom(
            db,
            app,
            scan,
            payload,
            storage_key=key,
            sbom_digest=digest,
            commit_sha=scan.commit_sha,
        )
        artifacts = {
            "source_sbom": {
                "storage_key": key,
                "digest": digest,
            }
        }
        scanner_failures: list[dict[str, str]] = []
        normalized_findings = []
        successful_sources: set[str] = set()

        scanner_steps = (
            ("osv", "osv.json", run_osv_scanner, normalize_osv_results),
            ("trivy", "trivy.json", run_trivy, normalize_trivy_results),
        )
        for source, filename, runner, normalizer in scanner_steps:
            scanner_output_path = workdir / f"{scan.id}-{filename}"
            try:
                scanner_payload = runner(target, scanner_output_path)
                if not scanner_output_path.exists():
                    scanner_output_path.write_text(json.dumps(scanner_payload), encoding="utf-8")
                scanner_key = artifact_key(str(repo.id), str(app.id), str(scan.id), filename)
                scanner_digest = store.put_file(scanner_key, scanner_output_path)
                artifacts[source] = {
                    "storage_key": scanner_key,
                    "digest": scanner_digest,
                }
                normalized_findings.extend(normalizer(scanner_payload))
                successful_sources.add(source)
            except Exception as exc:  # noqa: BLE001
                scanner_failures.append({"tool": source, "error": str(exc)})
                logger.warning(
                    "vulnerability scanner failed app_id=%s tool=%s error=%s",
                    app.id,
                    source,
                    exc,
                )

        persistence = upsert_findings(
            db,
            app,
            scan,
            normalized_findings,
            resolved_sources=successful_sources,
        )
        notifications = enqueue_finding_notifications(
            db,
            finding_ids=persistence.notification_finding_ids,
            scan_id=scan.id,
            settings=get_settings(),
        )
        if notifications:
            enqueue_job(
                db,
                JobType.notification,
                repository_id=repo.id,
                application_id=app.id,
                payload={"notification_ids": [str(notification.id) for notification in notifications]},
            )
        issue_requests = enqueue_github_issue_requests(
            db,
            finding_ids=persistence.notification_finding_ids,
        )
        if issue_requests:
            enqueue_job(
                db,
                JobType.issue_create,
                repository_id=repo.id,
                application_id=app.id,
                payload={"remediation_action_ids": [str(action.id) for action in issue_requests]},
            )
        if persistence.resolved_finding_ids:
            enqueue_job(
                db,
                JobType.issue_create,
                repository_id=repo.id,
                application_id=app.id,
                payload={
                    "operation": "close",
                    "finding_ids": [str(finding_id) for finding_id in persistence.resolved_finding_ids],
                },
            )
        scan.status = ScanStatus.partially_succeeded if scanner_failures else ScanStatus.succeeded
        scan.completed_at = now_utc()
        scan.result_summary = {
            "scanner_failure": bool(scanner_failures),
            "sbom_stored": True,
            "component_count": component_count,
            "finding_count": persistence.finding_count,
            "resolved_count": persistence.resolved_count,
            "notification_count": len(notifications),
            "issue_request_count": len(issue_requests),
            "issue_close_request_count": len(persistence.resolved_finding_ids),
            "scanner_failures": scanner_failures,
            "artifacts": artifacts,
        }
        return True
    except Exception as exc:  # noqa: BLE001
        scan.status = ScanStatus.failed
        scan.completed_at = now_utc()
        scan.error_message = str(exc)
        scan.result_summary = {"scanner_failure": True, "sbom_stored": False}
        logger.warning("application scan failed app_id=%s error=%s", app.id, exc)
        return False


def run_scan_job(db: Session, job: Job) -> None:
    payload = job.payload or {}
    repo_id = job.repository_id or payload.get("repository_id")
    if not repo_id:
        raise RuntimeError("scan job requires repository_id")
    repo_id = UUID(str(repo_id))
    repo = db.get(Repository, repo_id)
    if not repo:
        raise RuntimeError(f"repository not found: {repo_id}")
    trigger_type = TriggerType(payload.get("trigger_type") or TriggerType.manual.value)
    with tempfile.TemporaryDirectory(prefix="watchtower-") as tmp:
        temp_root = Path(tmp)
        root = clone_repository(repo, temp_root)
        apps = upsert_detected_applications(db, repo, root)
        store = ArtifactStore(get_settings())
        successes = 0
        for app in apps:
            if scan_application(db, repo, app, root, store, temp_root, trigger_type=trigger_type):
                successes += 1
        if successes == 0:
            raise RuntimeError("all application scans failed")


def latest_scan_for_application(db: Session, app: Application) -> Scan | None:
    return db.scalar(
        select(Scan)
        .where(Scan.application_id == app.id)
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


def _uuid_list_from_payload(payload: dict, *keys: str) -> list[UUID]:
    values: list[UUID] = []
    for key in keys:
        raw_value = payload.get(key)
        if not raw_value:
            continue
        raw_values = raw_value if isinstance(raw_value, list) else [raw_value]
        values.extend(UUID(str(item)) for item in raw_values)
    return values


def resolve_remediation_validation_targets(
    db: Session,
    job: Job,
) -> tuple[list[Application], list[RemediationAction]]:
    payload = job.payload or {}
    action_ids = _uuid_list_from_payload(payload, "remediation_action_ids", "action_ids", "remediation_action_id")
    finding_ids = _uuid_list_from_payload(payload, "finding_ids", "finding_id")
    application_ids = _uuid_list_from_payload(payload, "application_ids", "application_id")
    if job.application_id:
        application_ids.append(UUID(str(job.application_id)))

    actions: list[RemediationAction] = []
    if action_ids:
        actions = list(db.scalars(select(RemediationAction).where(RemediationAction.id.in_(action_ids))))
        if len(actions) != len(set(action_ids)):
            found_ids = {action.id for action in actions}
            missing_ids = [str(action_id) for action_id in action_ids if action_id not in found_ids]
            raise RuntimeError(f"remediation action not found: {', '.join(missing_ids)}")
        finding_ids.extend(action.finding_id for action in actions)

    applications_by_id: dict[UUID, Application] = {}
    if application_ids:
        applications = list(db.scalars(select(Application).where(Application.id.in_(application_ids))))
        if len(applications) != len(set(application_ids)):
            found_ids = {application.id for application in applications}
            missing_ids = [str(application_id) for application_id in application_ids if application_id not in found_ids]
            raise RuntimeError(f"application not found: {', '.join(missing_ids)}")
        applications_by_id.update({application.id: application for application in applications})

    if finding_ids:
        findings = list(db.scalars(select(Finding).where(Finding.id.in_(finding_ids))))
        if len(findings) != len(set(finding_ids)):
            found_ids = {finding.id for finding in findings}
            missing_ids = [str(finding_id) for finding_id in finding_ids if finding_id not in found_ids]
            raise RuntimeError(f"finding not found: {', '.join(missing_ids)}")
        for finding in findings:
            application = db.get(Application, finding.application_id)
            if application:
                applications_by_id[application.id] = application

    if not applications_by_id:
        raise RuntimeError("remediation validation job requires remediation_action_ids, finding_ids, or application_id")
    return list(applications_by_id.values()), actions


def record_remediation_validation_result(
    db: Session,
    actions: list[RemediationAction],
    app: Application,
    scan: Scan | None,
    *,
    success: bool,
) -> None:
    for action in actions:
        finding = db.get(Finding, action.finding_id)
        if not finding or finding.application_id != app.id:
            continue

        metadata = dict(action.metadata_json or {})
        if scan:
            metadata["validation_scan_id"] = str(scan.id)
            metadata["validation_scan_status"] = scan.status.value
        metadata["validation_status"] = "succeeded" if success else "failed"
        if success:
            metadata.pop("validation_error", None)
        else:
            error = scan.error_message if scan and scan.error_message else "validation scan failed"
            metadata["validation_error"] = error
        action.metadata_json = metadata


def run_remediation_validation_job(db: Session, job: Job) -> None:
    applications, actions = resolve_remediation_validation_targets(db, job)
    successes = 0
    failures = 0

    for app in applications:
        repo = db.get(Repository, app.repository_id)
        if not repo:
            raise RuntimeError(f"repository not found for application: {app.id}")

        with tempfile.TemporaryDirectory(prefix="watchtower-validation-") as tmp:
            temp_root = Path(tmp)
            root = clone_repository(repo, temp_root)
            success = scan_application(
                db,
                repo,
                app,
                root,
                ArtifactStore(get_settings()),
                temp_root,
                trigger_type=TriggerType.remediation_validation,
            )
            scan = latest_scan_for_application(db, app)
            record_remediation_validation_result(db, actions, app, scan, success=success)
            if success:
                successes += 1
            else:
                failures += 1

    logger.info(
        "remediation validation completed job_id=%s success_count=%s failure_count=%s",
        job.id,
        successes,
        failures,
    )
    if successes == 0:
        raise RuntimeError("all remediation validation scans failed")


def run_notification_job(db: Session, job: Job) -> None:
    notification_ids = [UUID(str(raw_id)) for raw_id in job.payload.get("notification_ids") or []]
    if notification_ids:
        stmt = select(Notification).where(
            Notification.id.in_(notification_ids),
            Notification.status == "queued",
        )
    else:
        stmt = select(Notification).where(Notification.status == "queued")

    settings = get_settings()
    for notification in db.scalars(stmt):
        deliver_notification(notification, settings=settings)


def run_issue_create_job(db: Session, job: Job) -> None:
    if job.payload.get("operation") == "close":
        finding_ids = [UUID(str(raw_id)) for raw_id in job.payload.get("finding_ids") or []]
        process_github_issue_closures(db, finding_ids=finding_ids, settings=get_settings())
        return

    action_ids = [UUID(str(raw_id)) for raw_id in job.payload.get("remediation_action_ids") or []]
    actions = process_github_issue_actions(db, action_ids=action_ids, settings=get_settings())
    if action_ids and len(actions) != len(action_ids):
        logger.warning(
            "some remediation actions were not processed for issue creation job_id=%s expected=%s updated=%s",
            job.id,
            len(action_ids),
            len(actions),
        )


def repository_sync_owner_from_payload(payload: dict) -> str | None:
    owner = payload.get("owner")
    if owner:
        return str(owner)

    body = payload.get("body")
    if not body:
        return None
    try:
        webhook_payload = json.loads(body) if isinstance(body, str) else body
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"repository sync webhook body is invalid JSON: {exc}") from exc
    if not isinstance(webhook_payload, dict):
        return None

    repository = webhook_payload.get("repository")
    if isinstance(repository, dict):
        repository_owner = repository.get("owner")
        if isinstance(repository_owner, dict) and repository_owner.get("login"):
            return str(repository_owner["login"])

    organization = webhook_payload.get("organization")
    if isinstance(organization, dict) and organization.get("login"):
        return str(organization["login"])
    return None


def run_repository_sync_job(db: Session, job: Job) -> None:
    owner = repository_sync_owner_from_payload(job.payload or {})
    if not owner:
        raise RuntimeError("repository sync job requires owner")
    repositories = sync_github_repositories(db, owner, get_settings())
    logger.info("repository sync completed owner=%s synced_count=%s", owner, len(repositories))


def handle_job(db: Session, job: Job) -> None:
    if job.job_type == JobType.scan:
        run_scan_job(db, job)
    elif job.job_type == JobType.remediation_validation:
        run_remediation_validation_job(db, job)
    elif job.job_type == JobType.notification:
        run_notification_job(db, job)
    elif job.job_type == JobType.issue_create:
        run_issue_create_job(db, job)
    elif job.job_type == JobType.repository_sync:
        run_repository_sync_job(db, job)
    else:
        logger.info("job type placeholder job_type=%s payload=%s", job.job_type, json.dumps(job.payload))


def work_once(worker_id: str) -> bool:
    with SessionLocal() as db:
        job = lock_next_job(db, worker_id)
        if not job:
            db.commit()
            return False
        try:
            handle_job(db, job)
            mark_job_succeeded(job)
            db.commit()
            logger.info("job succeeded id=%s type=%s", job.id, job.job_type)
        except Exception as exc:  # noqa: BLE001
            logger.exception("job failed id=%s", job.id)
            mark_job_failed(job, str(exc))
            db.commit()
    return True


def main() -> None:
    settings = get_settings()
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    logger.info("worker started id=%s", worker_id)
    while True:
        did_work = work_once(worker_id)
        if not did_work:
            time.sleep(settings.worker_poll_interval_seconds)


if __name__ == "__main__":
    main()
