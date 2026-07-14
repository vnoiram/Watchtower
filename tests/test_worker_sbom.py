import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Component,
    Finding,
    Job,
    JobType,
    Notification,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    Severity,
    SourceClassification,
)
from api.app.services.scanner import NormalizedFinding
from worker import runner


class FakeArtifactStore:
    def __init__(self) -> None:
        self.keys: list[str] = []

    def put_file(self, key: str, path: Path) -> str:
        assert path.exists()
        self.keys.append(key)
        return "sha256-digest"


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_repo_and_app(db: Session, tmp_path: Path) -> tuple[Repository, Application]:
    repo = Repository(
        provider=RepositoryProvider.local,
        provider_repository_id="repo-1",
        owner="local",
        name="demo",
        local_path=str(tmp_path),
        source_classification=SourceClassification.private,
        archived=False,
        fork=False,
        topics=[],
    )
    db.add(repo)
    db.flush()
    app = Application(
        repository_id=repo.id,
        name="demo",
        path=".",
        application_type=ApplicationType.api,
    )
    db.add(app)
    db.flush()
    return repo, app


def disable_notifications(monkeypatch) -> None:
    monkeypatch.setattr(runner, "get_settings", lambda: Settings())


def test_scan_application_persists_successful_syft_sbom(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path)
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "fastapi", "version": "0.111.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["component_count"] == 1
        assert scan.result_summary["finding_count"] == 0
        assert scan.result_summary["resolved_count"] == 0
        assert scan.result_summary["notification_count"] == 0
        assert scan.result_summary["scanner_failures"] == []
        assert store.keys == [
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/source-sbom.cdx.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/osv.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/trivy.json",
        ]
        assert db.scalar(select(Component).where(Component.purl == "pkg:generic/fastapi@0.111.0"))


def test_scan_application_persists_vulnerability_findings(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path)
        app.internet_exposed = True
        app.production = True
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "demo", "version": "1.0.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(
            runner,
            "run_osv_scanner",
            lambda *_: {
                "results": [
                    {
                        "package": {"name": "demo", "ecosystem": "PyPI", "version": "1.0.0"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-123",
                                "summary": "demo issue",
                                "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                            }
                        ],
                    }
                ]
            },
        )
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        finding = db.scalar(select(Finding))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["finding_count"] == 1
        assert scan.result_summary["notification_count"] == 0
        assert finding.severity == Severity.high
        assert finding.risk_score == 10.0


def test_scan_application_enqueues_chat_notifications(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        monkeypatch.setattr(
            runner,
            "get_settings",
            lambda: Settings(
                slack_webhook_url="https://hooks.slack.test/demo",
                discord_webhook_url="https://discord.test/webhook",
            ),
        )
        repo, app = create_repo_and_app(db, tmp_path)
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "demo", "version": "1.0.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(
            runner,
            "run_osv_scanner",
            lambda *_: {
                "results": [
                    {
                        "package": {"name": "demo", "ecosystem": "PyPI", "version": "1.0.0"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-123",
                                "summary": "demo issue",
                                "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}],
                            }
                        ],
                    }
                ]
            },
        )
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        notifications = list(db.scalars(select(Notification)))
        job = db.scalar(select(Job).where(Job.job_type == JobType.notification))
        assert scan.result_summary["notification_count"] == 2
        assert {notification.channel for notification in notifications} == {"slack", "discord"}
        assert job
        assert set(job.payload["notification_ids"]) == {str(notification.id) for notification in notifications}


def test_scan_application_records_partial_success_for_scanner_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path)
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "demo", "version": "1.0.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        def fake_normalize_trivy_results(_: dict) -> list[NormalizedFinding]:
            return [
                NormalizedFinding(
                    source="trivy",
                    vulnerability_id="CVE-2026-0001",
                    package_name="demo",
                    package_version="1.0.0",
                    ecosystem="npm",
                    purl="pkg:npm/demo@1.0.0",
                    severity=Severity.medium,
                )
            ]

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: (_ for _ in ()).throw(RuntimeError("osv missing")))
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "normalize_trivy_results", fake_normalize_trivy_results)

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.partially_succeeded
        assert scan.result_summary["scanner_failure"] is True
        assert scan.result_summary["scanner_failures"] == [{"tool": "osv", "error": "osv missing"}]
        assert scan.result_summary["finding_count"] == 1
        assert scan.result_summary["notification_count"] == 0
        assert db.scalar(select(Finding))


def test_scan_application_records_failure_without_raising(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path)

        def fake_run_syft(_: Path, __: Path) -> dict:
            raise RuntimeError("syft missing")

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)

        assert not runner.scan_application(db, repo, app, tmp_path, FakeArtifactStore(), tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.failed
        assert scan.result_summary == {"scanner_failure": True, "sbom_stored": False}
        assert scan.error_message == "syft missing"


def test_run_notification_job_delivers_queued_notifications(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path)
        notification = Notification(
            channel="slack",
            severity=Severity.high,
            subject="High vulnerability detected: GHSA-123",
            body="body",
            status="queued",
            metadata_json={"notification_kind": "vulnerability_alert"},
        )
        job = Job(
            job_type=JobType.notification,
            repository_id=repo.id,
            application_id=app.id,
            payload={"notification_ids": []},
        )
        db.add_all([notification, job])
        db.flush()
        job.payload = {"notification_ids": [str(notification.id)]}
        delivered = []

        def fake_deliver(target: Notification, *, settings: Settings) -> None:
            delivered.append((target.id, settings))
            target.status = "sent"

        monkeypatch.setattr(runner, "deliver_notification", fake_deliver)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(slack_webhook_url="https://example.test"))

        runner.run_notification_job(db, job)

        assert delivered == [(notification.id, runner.get_settings())]
        assert notification.status == "sent"
