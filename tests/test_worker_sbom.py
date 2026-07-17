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
    FindingStatus,
    Job,
    JobType,
    Notification,
    RemediationAction,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    Severity,
    SourceClassification,
    Vulnerability,
    TriggerType,
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


def create_repo_and_app(
    db: Session,
    tmp_path: Path,
    *,
    provider: RepositoryProvider = RepositoryProvider.local,
) -> tuple[Repository, Application]:
    repo = Repository(
        provider=provider,
        provider_repository_id="repo-1",
        owner="local",
        name="demo",
        url="https://github.com/local/demo" if provider == RepositoryProvider.github else None,
        local_path=str(tmp_path) if provider != RepositoryProvider.github else None,
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


def create_finding(
    db: Session,
    app: Application,
    *,
    status: FindingStatus = FindingStatus.open,
    fixed_version: str | None = "1.0.1",
) -> Finding:
    component = Component(
        purl=f"pkg:pypi/demo-{app.id}@1.0.0",
        ecosystem="PyPI",
        name=f"demo-{app.id}",
        version="1.0.0",
    )
    vulnerability = Vulnerability(
        source="osv",
        external_id=f"GHSA-{app.id}",
        severity=Severity.high,
        references=[],
    )
    db.add_all([component, vulnerability])
    db.flush()
    finding = Finding(
        application_id=app.id,
        component_id=component.id,
        vulnerability_id=vulnerability.id,
        status=status,
        severity=Severity.high,
        fixed_version=fixed_version,
        risk_score=8.0,
    )
    db.add(finding)
    db.flush()
    return finding


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
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["component_count"] == 1
        assert scan.result_summary["finding_count"] == 0
        assert scan.result_summary["resolved_count"] == 0
        assert scan.result_summary["notification_count"] == 0
        assert scan.result_summary["issue_request_count"] == 0
        assert scan.result_summary["issue_close_request_count"] == 0
        assert scan.result_summary["scanner_failures"] == []
        assert store.keys == [
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/source-sbom.cdx.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/osv.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/trivy.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/grype.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/gitleaks.json",
            f"repositories/{repo.id}/applications/{app.id}/scans/{scan.id}/semgrep.json",
        ]
        assert scan.result_summary["secrets"] == []
        assert scan.result_summary["sast"] == []
        assert db.scalar(select(Component).where(Component.purl == "pkg:generic/fastapi@0.111.0"))


def test_scan_application_accepts_remediation_validation_trigger(monkeypatch, tmp_path: Path) -> None:
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

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(
            db,
            repo,
            app,
            tmp_path,
            store,
            tmp_path,
            trigger_type=TriggerType.remediation_validation,
        )
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.trigger_type == TriggerType.remediation_validation


def test_scan_application_records_secrets_and_sast_findings(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path)
        store = FakeArtifactStore()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(
            runner,
            "run_gitleaks",
            lambda *_: [{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "config.py", "StartLine": 3}],
        )
        monkeypatch.setattr(
            runner,
            "run_semgrep",
            lambda *_: {
                "results": [
                    {
                        "check_id": "python.lang.security.audit.dangerous-eval",
                        "path": "app/main.py",
                        "start": {"line": 42},
                        "extra": {"message": "Detected use of eval", "severity": "ERROR"},
                    }
                ]
            },
        )

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["secrets"] == [
            {
                "type": "secret",
                "rule_id": "generic-api-key",
                "severity": "high",
                "path": "config.py",
                "title": "Generic API Key",
                "detail": "config.py:3",
                "commit": None,
                "fingerprint": None,
            }
        ]
        assert scan.result_summary["sast"] == [
            {
                "type": "sast",
                "rule_id": "python.lang.security.audit.dangerous-eval",
                "severity": "high",
                "path": "app/main.py",
                "title": "Detected use of eval",
                "detail": "app/main.py:42",
            }
        ]


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
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        finding = db.scalar(select(Finding))
        assert scan.status == ScanStatus.succeeded
        assert scan.result_summary["finding_count"] == 1
        assert scan.result_summary["notification_count"] == 0
        assert scan.result_summary["issue_request_count"] == 0
        assert scan.result_summary["issue_close_request_count"] == 0
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
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        notifications = list(db.scalars(select(Notification)))
        job = db.scalar(select(Job).where(Job.job_type == JobType.notification))
        assert scan.result_summary["notification_count"] == 2
        assert scan.result_summary["issue_request_count"] == 0
        assert scan.result_summary["issue_close_request_count"] == 0
        assert {notification.channel for notification in notifications} == {"slack", "discord"}
        assert job
        assert set(job.payload["notification_ids"]) == {str(notification.id) for notification in notifications}


def test_scan_application_enqueues_github_issue_requests(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
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
                                "affected": [
                                    {
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}
                                        ]
                                    }
                                ],
                            }
                        ],
                    }
                ]
            },
        )
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        action = db.scalar(select(RemediationAction))
        job = db.scalar(select(Job).where(Job.job_type == JobType.issue_create))
        assert scan.result_summary["issue_request_count"] == 1
        assert scan.result_summary["issue_close_request_count"] == 0
        assert action.action_type == "github_issue"
        assert action.status == "queued"
        assert job
        assert job.payload["remediation_action_ids"] == [str(action.id)]


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
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "normalize_trivy_results", fake_normalize_trivy_results)

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        assert scan.status == ScanStatus.partially_succeeded
        assert scan.result_summary["scanner_failure"] is True
        assert scan.result_summary["scanner_failures"] == [{"tool": "osv", "error": "osv missing"}]
        assert scan.result_summary["finding_count"] == 1
        assert scan.result_summary["notification_count"] == 0
        assert scan.result_summary["issue_request_count"] == 0
        assert scan.result_summary["issue_close_request_count"] == 0
        assert db.scalar(select(Finding))


def test_scan_application_enqueues_github_issue_closures(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            status=FindingStatus.open,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            metadata_json={"finding_id": str(finding.id), "repository_id": str(repo.id)},
        )
        db.add(action)
        db.flush()
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
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        assert runner.scan_application(db, repo, app, tmp_path, store, tmp_path)
        db.flush()

        scan = db.scalar(select(Scan))
        close_job = next(
            job
            for job in db.scalars(select(Job).where(Job.job_type == JobType.issue_create))
            if job.payload.get("operation") == "close"
        )
        assert finding.status == FindingStatus.resolved
        assert scan.result_summary["resolved_count"] == 1
        assert scan.result_summary["issue_close_request_count"] == 1
        assert close_job
        assert close_job.payload == {"operation": "close", "finding_ids": [str(finding.id)]}


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


def test_run_issue_create_job_processes_payload_action_ids(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="queued",
            provider="github",
            metadata_json={"finding_id": str(finding.id)},
        )
        job = Job(
            job_type=JobType.issue_create,
            repository_id=repo.id,
            application_id=app.id,
            payload={"remediation_action_ids": []},
        )
        db.add_all([action, job])
        db.flush()
        job.payload = {"remediation_action_ids": [str(action.id)]}
        calls = []

        def fake_process(db_arg: Session, *, action_ids: list, settings: Settings) -> list[RemediationAction]:
            calls.append((db_arg, action_ids, settings))
            action.status = "created"
            return [action]

        monkeypatch.setattr(runner, "process_github_issue_actions", fake_process)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_issue_create_job(db, job)

        assert calls == [(db, [action.id], runner.get_settings())]
        assert action.status == "created"


def test_run_issue_create_job_processes_all_when_payload_empty(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        queued = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="queued",
            provider="github",
            metadata_json={"finding_id": str(finding.id), "repository_id": str(repo.id)},
        )
        pending = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="pending_provider",
            provider="github",
            metadata_json={"finding_id": str(finding.id), "repository_id": str(repo.id)},
        )
        created = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            metadata_json={"finding_id": str(finding.id), "repository_id": str(repo.id)},
        )
        job = Job(
            job_type=JobType.issue_create,
            repository_id=repo.id,
            application_id=app.id,
            payload={},
        )
        db.add_all([queued, pending, created, job])
        db.flush()

        def fake_process(db_arg: Session, *, action_ids: list, settings: Settings) -> list[RemediationAction]:
            assert db_arg is db
            assert action_ids == []
            queued.status = "created"
            pending.status = "failed"
            return [queued, pending]

        monkeypatch.setattr(runner, "process_github_issue_actions", fake_process)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_issue_create_job(db, job)

        assert queued.status == "created"
        assert pending.status == "failed"
        assert created.status == "created"


def test_run_issue_create_job_processes_close_operation(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            status=FindingStatus.resolved,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        job = Job(
            job_type=JobType.issue_create,
            repository_id=repo.id,
            application_id=app.id,
            payload={"operation": "close", "finding_ids": [str(finding.id)]},
        )
        db.add(job)
        db.flush()
        calls = []

        def fake_close(db_arg: Session, *, finding_ids: list, settings: Settings) -> list[RemediationAction]:
            calls.append((db_arg, finding_ids, settings))
            return []

        monkeypatch.setattr(runner, "process_github_issue_closures", fake_close)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_issue_create_job(db, job)

        assert calls == [(db, [finding.id], runner.get_settings())]


def test_run_remediation_validation_job_scans_action_application(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            status=FindingStatus.open,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            metadata_json={"repository_id": str(repo.id), "validation_error": "previous"},
        )
        db.add(action)
        db.flush()
        job = Job(
            job_type=JobType.remediation_validation,
            repository_id=repo.id,
            application_id=app.id,
            payload={"remediation_action_ids": [str(action.id)]},
        )
        db.add(job)
        db.flush()

        def fake_run_syft(_: Path, output_path: Path) -> dict:
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [{"type": "library", "name": "demo", "version": "1.0.0"}],
            }
            output_path.write_text(json.dumps(payload), encoding="utf-8")
            return payload

        monkeypatch.setattr(runner, "clone_repository", lambda *_: tmp_path)
        monkeypatch.setattr(runner, "ArtifactStore", lambda *_: FakeArtifactStore())
        monkeypatch.setattr(runner, "run_syft", fake_run_syft)
        monkeypatch.setattr(runner, "run_osv_scanner", lambda *_: {"results": []})
        monkeypatch.setattr(runner, "run_trivy", lambda *_: {"Results": []})
        monkeypatch.setattr(runner, "run_grype", lambda *_: {"matches": []})
        monkeypatch.setattr(runner, "run_gitleaks", lambda *_: [])
        monkeypatch.setattr(runner, "run_semgrep", lambda *_: {"results": []})

        runner.run_remediation_validation_job(db, job)
        db.flush()

        scan = db.scalar(select(Scan).where(Scan.trigger_type == TriggerType.remediation_validation))
        close_job = db.scalar(
            select(Job).where(
                Job.job_type == JobType.issue_create,
                Job.payload["operation"].as_string() == "close",
            )
        )
        assert finding.status == FindingStatus.resolved
        assert scan.status == ScanStatus.succeeded
        assert action.status == "created"
        assert action.metadata_json["validation_scan_id"] == str(scan.id)
        assert action.metadata_json["validation_scan_status"] == "succeeded"
        assert action.metadata_json["validation_status"] == "succeeded"
        assert "validation_error" not in action.metadata_json
        assert close_job.payload == {"operation": "close", "finding_ids": [str(finding.id)]}


def test_run_remediation_validation_job_records_failed_validation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        disable_notifications(monkeypatch)
        repo, app = create_repo_and_app(db, tmp_path, provider=RepositoryProvider.github)
        component = Component(
            purl="pkg:pypi/demo@1.0.0",
            ecosystem="PyPI",
            name="demo",
            version="1.0.0",
        )
        vulnerability = Vulnerability(
            source="osv",
            external_id="GHSA-123",
            severity=Severity.high,
            references=[],
        )
        db.add_all([component, vulnerability])
        db.flush()
        finding = Finding(
            application_id=app.id,
            component_id=component.id,
            vulnerability_id=vulnerability.id,
            status=FindingStatus.open,
            severity=Severity.high,
            fixed_version="1.0.1",
            risk_score=8.0,
        )
        db.add(finding)
        db.flush()
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            metadata_json={"repository_id": str(repo.id)},
        )
        db.add(action)
        db.flush()
        job = Job(
            job_type=JobType.remediation_validation,
            payload={"remediation_action_ids": [str(action.id)]},
        )
        db.add(job)
        db.flush()

        def fake_run_syft(_: Path, __: Path) -> dict:
            raise RuntimeError("syft missing")

        monkeypatch.setattr(runner, "clone_repository", lambda *_: tmp_path)
        monkeypatch.setattr(runner, "ArtifactStore", lambda *_: FakeArtifactStore())
        monkeypatch.setattr(runner, "run_syft", fake_run_syft)

        try:
            runner.run_remediation_validation_job(db, job)
        except RuntimeError as exc:
            assert "all remediation validation scans failed" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")
        db.flush()

        scan = db.scalar(select(Scan).where(Scan.trigger_type == TriggerType.remediation_validation))
        assert scan.status == ScanStatus.failed
        assert action.status == "created"
        assert action.metadata_json["validation_scan_id"] == str(scan.id)
        assert action.metadata_json["validation_scan_status"] == "failed"
        assert action.metadata_json["validation_status"] == "failed"
        assert action.metadata_json["validation_error"] == "syft missing"


def test_run_remediation_validation_job_requires_target() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.remediation_validation, payload={})
        db.add(job)
        db.flush()

        try:
            runner.run_remediation_validation_job(db, job)
        except RuntimeError as exc:
            assert "requires remediation_action_ids" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")


def test_handle_job_dispatches_remediation_validation(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.remediation_validation, payload={"application_ids": []})
        db.add(job)
        db.flush()
        calls = []

        def fake_run_remediation_validation_job(db_arg: Session, job_arg: Job) -> None:
            calls.append((db_arg, job_arg))

        monkeypatch.setattr(
            runner,
            "run_remediation_validation_job",
            fake_run_remediation_validation_job,
        )

        runner.handle_job(db, job)

        assert calls == [(db, job)]


def test_run_ai_fix_job_passes_finding_ids_to_service(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app = create_repo_and_app(db, tmp_path)
        finding = create_finding(db, app)
        job = Job(job_type=JobType.ai_fix, payload={"finding_ids": [str(finding.id)]})
        db.add(job)
        db.flush()
        calls = []

        def fake_enqueue_ai_fix_requests(
            db_arg: Session,
            *,
            finding_ids: list,
            application_id,
        ) -> list[RemediationAction]:
            calls.append((db_arg, finding_ids, application_id))
            return []

        monkeypatch.setattr(runner, "enqueue_ai_fix_requests", fake_enqueue_ai_fix_requests)

        runner.run_ai_fix_job(db, job)

        assert calls == [(db, [finding.id], None)]


def test_run_ai_fix_job_supports_application_id(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app = create_repo_and_app(db, tmp_path)
        job = Job(job_type=JobType.ai_fix, payload={"application_id": str(app.id)})
        db.add(job)
        db.flush()
        calls = []

        def fake_enqueue_ai_fix_requests(
            db_arg: Session,
            *,
            finding_ids: list,
            application_id,
        ) -> list[RemediationAction]:
            calls.append((db_arg, finding_ids, application_id))
            return []

        monkeypatch.setattr(runner, "enqueue_ai_fix_requests", fake_enqueue_ai_fix_requests)

        runner.run_ai_fix_job(db, job)

        assert calls == [(db, [], app.id)]


def test_run_ai_fix_job_requires_target() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.ai_fix, payload={})
        db.add(job)
        db.flush()

        try:
            runner.run_ai_fix_job(db, job)
        except RuntimeError as exc:
            assert str(exc) == "ai fix job requires finding_ids or application_id"
        else:
            raise AssertionError("expected RuntimeError")


def test_handle_job_dispatches_ai_fix(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.ai_fix, payload={"finding_ids": []})
        db.add(job)
        db.flush()
        calls = []

        def fake_run_ai_fix_job(db_arg: Session, job_arg: Job) -> None:
            calls.append((db_arg, job_arg))

        monkeypatch.setattr(runner, "run_ai_fix_job", fake_run_ai_fix_job)

        runner.handle_job(db, job)

        assert calls == [(db, job)]


def test_run_repository_sync_job_syncs_owner_payload(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.repository_sync, payload={"owner": "acme"})
        db.add(job)
        db.flush()
        calls = []

        def fake_sync(db_arg: Session, owner: str, settings: Settings) -> list[Repository]:
            calls.append((db_arg, owner, settings))
            return []

        monkeypatch.setattr(runner, "sync_github_repositories", fake_sync)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_repository_sync_job(db, job)

        assert calls == [(db, "acme", runner.get_settings())]


def test_run_repository_sync_job_extracts_owner_from_webhook_body(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(
            job_type=JobType.repository_sync,
            payload={"body": json.dumps({"repository": {"owner": {"login": "repo-owner"}}})},
        )
        db.add(job)
        db.flush()
        calls = []

        def fake_sync(db_arg: Session, owner: str, settings: Settings) -> list[Repository]:
            calls.append((db_arg, owner, settings))
            return []

        monkeypatch.setattr(runner, "sync_github_repositories", fake_sync)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_repository_sync_job(db, job)

        assert calls == [(db, "repo-owner", runner.get_settings())]


def test_run_repository_sync_job_extracts_owner_from_webhook_organization(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(
            job_type=JobType.repository_sync,
            payload={"body": json.dumps({"organization": {"login": "org-owner"}})},
        )
        db.add(job)
        db.flush()
        calls = []

        def fake_sync(db_arg: Session, owner: str, settings: Settings) -> list[Repository]:
            calls.append((db_arg, owner, settings))
            return []

        monkeypatch.setattr(runner, "sync_github_repositories", fake_sync)
        monkeypatch.setattr(runner, "get_settings", lambda: Settings(github_token="token"))

        runner.run_repository_sync_job(db, job)

        assert calls == [(db, "org-owner", runner.get_settings())]


def test_run_repository_sync_job_requires_owner() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.repository_sync, payload={"body": json.dumps({"zen": "ok"})})
        db.add(job)
        db.flush()

        try:
            runner.run_repository_sync_job(db, job)
        except RuntimeError as exc:
            assert "requires owner" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")


def test_handle_job_dispatches_repository_sync(monkeypatch) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        job = Job(job_type=JobType.repository_sync, payload={"owner": "acme"})
        db.add(job)
        db.flush()
        calls = []

        def fake_run_repository_sync_job(db_arg: Session, job_arg: Job) -> None:
            calls.append((db_arg, job_arg))

        monkeypatch.setattr(runner, "run_repository_sync_job", fake_run_repository_sync_job)

        runner.handle_job(db, job)

        assert calls == [(db, job)]


def test_run_scan_job_uses_schedule_trigger_from_payload(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path)
        job = Job(
            job_type=JobType.scan,
            repository_id=repo.id,
            payload={"repository_id": str(repo.id), "trigger_type": "schedule"},
        )
        db.add(job)
        db.flush()
        trigger_types: list[TriggerType] = []

        monkeypatch.setattr(runner, "clone_repository", lambda *_: tmp_path)
        monkeypatch.setattr(runner, "upsert_detected_applications", lambda *_: [app])
        monkeypatch.setattr(runner, "ArtifactStore", lambda *_: FakeArtifactStore())
        monkeypatch.setattr(runner, "get_settings", lambda: Settings())

        def fake_scan_application(*args, trigger_type: TriggerType = TriggerType.manual) -> bool:
            trigger_types.append(trigger_type)
            return True

        monkeypatch.setattr(runner, "scan_application", fake_scan_application)

        runner.run_scan_job(db, job)

        assert trigger_types == [TriggerType.schedule]


def test_run_scan_job_defaults_to_manual_trigger(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo, app = create_repo_and_app(db, tmp_path)
        job = Job(job_type=JobType.scan, payload={"repository_id": str(repo.id)})
        db.add(job)
        db.flush()
        trigger_types: list[TriggerType] = []

        monkeypatch.setattr(runner, "clone_repository", lambda *_: tmp_path)
        monkeypatch.setattr(runner, "upsert_detected_applications", lambda *_: [app])
        monkeypatch.setattr(runner, "ArtifactStore", lambda *_: FakeArtifactStore())
        monkeypatch.setattr(runner, "get_settings", lambda: Settings())

        def fake_scan_application(*args, trigger_type: TriggerType = TriggerType.schedule) -> bool:
            trigger_types.append(trigger_type)
            return True

        monkeypatch.setattr(runner, "scan_application", fake_scan_application)

        runner.run_scan_job(db, job)

        assert trigger_types == [TriggerType.manual]
