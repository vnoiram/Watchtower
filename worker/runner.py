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
from api.app.services.jobs import lock_next_job, mark_job_failed, mark_job_succeeded
from api.app.services.registry import detect_applications

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


def create_failed_scan(db: Session, app: Application, error: str) -> None:
    db.add(
        Scan(
            application_id=app.id,
            trigger_type=TriggerType.manual,
            status=ScanStatus.failed,
            tool="watchtower-worker",
            result_summary={"scanner_failure": True},
            error_message=error,
            started_at=now_utc(),
            completed_at=now_utc(),
        )
    )


def run_scan_job(db: Session, job: Job) -> None:
    repo_id = job.repository_id or job.payload.get("repository_id")
    if not repo_id:
        raise RuntimeError("scan job requires repository_id")
    repo = db.get(Repository, repo_id)
    if not repo:
        raise RuntimeError(f"repository not found: {repo_id}")
    with tempfile.TemporaryDirectory(prefix="watchtower-") as tmp:
        root = clone_repository(repo, Path(tmp))
        apps = upsert_detected_applications(db, repo, root)
        for app in apps:
            scan = Scan(
                application_id=app.id,
                trigger_type=TriggerType.manual,
                status=ScanStatus.succeeded,
                tool="watchtower-worker",
                result_summary={"applications_detected": len(apps), "scanner_failure": False},
                started_at=now_utc(),
                completed_at=now_utc(),
            )
            db.add(scan)


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

