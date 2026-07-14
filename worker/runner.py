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

from sqlalchemy.orm import Session

from api.app.config import get_settings
from api.app.database import SessionLocal
from api.app.models import (
    Application,
    ApplicationType,
    Job,
    JobType,
    Repository,
    Scan,
    ScanStatus,
    Technology,
    TriggerType,
    now_utc,
)
from api.app.services.artifacts import ArtifactStore, artifact_key
from api.app.services.jobs import lock_next_job, mark_job_failed, mark_job_succeeded
from api.app.services.registry import detect_applications
from api.app.services.sbom import upsert_source_sbom

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


def scan_application(
    db: Session,
    repo: Repository,
    app: Application,
    root: Path,
    store: ArtifactStore,
    workdir: Path,
) -> bool:
    started = now_utc()
    scan = Scan(
        application_id=app.id,
        trigger_type=TriggerType.manual,
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
        scan.status = ScanStatus.succeeded
        scan.completed_at = now_utc()
        scan.result_summary = {
            "scanner_failure": False,
            "sbom_stored": True,
            "component_count": component_count,
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
    repo_id = job.repository_id or job.payload.get("repository_id")
    if not repo_id:
        raise RuntimeError("scan job requires repository_id")
    repo = db.get(Repository, repo_id)
    if not repo:
        raise RuntimeError(f"repository not found: {repo_id}")
    with tempfile.TemporaryDirectory(prefix="watchtower-") as tmp:
        temp_root = Path(tmp)
        root = clone_repository(repo, temp_root)
        apps = upsert_detected_applications(db, repo, root)
        store = ArtifactStore(get_settings())
        successes = 0
        for app in apps:
            if scan_application(db, repo, app, root, store, temp_root):
                successes += 1
        if successes == 0:
            raise RuntimeError("all application scans failed")


def handle_job(db: Session, job: Job) -> None:
    if job.job_type == JobType.scan:
        run_scan_job(db, job)
    elif job.job_type == JobType.repository_sync:
        logger.info("repository sync placeholder payload=%s", json.dumps(job.payload))
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
