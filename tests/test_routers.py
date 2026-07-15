from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Component,
    Finding,
    FindingStatus,
    Job,
    JobStatus,
    JobType,
    Lifecycle,
    Notification,
    RemediationAction,
    Repository,
    RepositoryProvider,
    Sbom,
    SbomComponent,
    Scan,
    ScanStatus,
    Severity,
    SourceClassification,
    Technology,
    TriggerType,
    VexStatement,
    VexStatus,
    Vulnerability,
    now_utc,
)
from api.app.routers.applications import list_applications
from api.app.routers.ai_fix import list_ai_fix_actions, list_ai_fix_candidates
from api.app.routers.artifacts import list_artifacts
from api.app.routers.auto_merge import list_auto_merge_eligibility
from api.app.routers.components import list_component_applications, list_components
from api.app.routers.dashboard import dashboard_summary
from api.app.routers.findings import list_findings
from api.app.routers.findings import enqueue_github_issue as enqueue_github_issue_endpoint
from api.app.routers.isolated_lane import list_isolated_lane
from api.app.routers.job_health import list_job_health
from api.app.routers.maintenance import list_application_maintenance_candidates
from api.app.routers.notifications import list_notifications
from api.app.routers.remediation import (
    list_github_issue_actions,
    list_issue_closures,
    list_remediation_candidates,
    list_remediation_validations,
)
from api.app.routers.remediation_actions import list_remediation_actions
from api.app.routers.scan_health import list_scan_health
from api.app.routers.sbom_coverage import list_sbom_coverage
from api.app.routers.sboms import list_sboms
from api.app.routers.sla import list_sla_findings
from api.app.routers.technologies import list_technologies
from api.app.routers.vex import list_vex_statements
from api.app.routers.vulnerabilities import list_vulnerabilities
from worker.runner import upsert_detected_applications


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_repository(db: Session, name: str = "demo") -> Repository:
    repo = Repository(
        provider=RepositoryProvider.github,
        provider_repository_id=name,
        owner="local",
        name=name,
        url="https://github.com/local/demo",
        source_classification=SourceClassification.private,
        archived=False,
        fork=False,
        topics=[],
    )
    db.add(repo)
    db.flush()
    return repo


def create_application(db: Session, repo: Repository, name: str = "demo") -> Application:
    app = Application(
        repository_id=repo.id,
        name=name,
        path="." if name == "demo" else name,
        application_type=ApplicationType.api,
    )
    db.add(app)
    db.flush()
    return app


def create_finding(
    db: Session,
    app: Application,
    *,
    severity: Severity,
    status: FindingStatus = FindingStatus.open,
    risk_score: float = 0.0,
    fixed_version: str | None = "1.0.1",
) -> Finding:
    component = Component(purl=f"pkg:pypi/{severity.value}-{status.value}@1.0.0", ecosystem="pypi", name=f"{severity.value}-pkg", version="1.0.0")
    vulnerability = Vulnerability(source="osv", external_id=f"{severity.value}-{status.value}", severity=severity)
    db.add_all([component, vulnerability])
    db.flush()
    finding = Finding(
        application_id=app.id,
        component_id=component.id,
        vulnerability_id=vulnerability.id,
        status=status,
        severity=severity,
        risk_score=risk_score,
        fixed_version=fixed_version,
    )
    db.add(finding)
    db.flush()
    return finding


def test_list_applications_returns_null_latest_scan_for_unscanned_application() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)

        page = list_applications(db=db, _=None)

        assert len(page.items) == 1
        assert page.items[0]["id"] == str(app.id)
        assert page.items[0]["latest_scan_at"] is None
        assert page.items[0]["latest_scan_status"] is None


def test_list_applications_returns_latest_scan_by_created_at_then_id() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        older = now_utc() - timedelta(hours=2)
        newest = now_utc()
        db.add_all(
            [
                Scan(
                    id=UUID("aaaaaaaa-0000-0000-0000-000000000001"),
                    application_id=app.id,
                    trigger_type=TriggerType.manual,
                    status=ScanStatus.failed,
                    created_at=older,
                ),
                Scan(
                    id=UUID("bbbbbbbb-0000-0000-0000-000000000002"),
                    application_id=app.id,
                    trigger_type=TriggerType.manual,
                    status=ScanStatus.running,
                    created_at=newest,
                ),
                Scan(
                    id=UUID("cccccccc-0000-0000-0000-000000000003"),
                    application_id=app.id,
                    trigger_type=TriggerType.manual,
                    status=ScanStatus.succeeded,
                    created_at=newest,
                ),
            ]
        )
        db.flush()

        page = list_applications(db=db, _=None)

        assert page.items[0]["latest_scan_at"] == newest.replace(tzinfo=None).isoformat()
        assert page.items[0]["latest_scan_status"] == "succeeded"


def test_list_findings_filters_by_status_and_critical_severity() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        critical = create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        create_finding(db, app, severity=Severity.high, risk_score=8.1)
        create_finding(db, app, severity=Severity.critical, status=FindingStatus.resolved, risk_score=9.9)

        page = list_findings(db=db, _=None, status=FindingStatus.open, severity=Severity.critical)

        assert [item["id"] for item in page.items] == [str(critical.id)]


def test_list_findings_filters_by_status_and_high_severity() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        high = create_finding(db, app, severity=Severity.high, risk_score=8.1)
        create_finding(db, app, severity=Severity.high, status=FindingStatus.resolved, risk_score=8.4)

        page = list_findings(db=db, _=None, status=FindingStatus.open, severity=Severity.high)

        assert [item["id"] for item in page.items] == [str(high.id)]


def test_upsert_detected_applications_does_not_duplicate_technology(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")

        upsert_detected_applications(db, repo, tmp_path)
        upsert_detected_applications(db, repo, tmp_path)

        technologies = list(db.scalars(select(Technology)))
        assert len(technologies) == 1
        assert technologies[0].name == "python"


def test_list_technologies_returns_application_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        db.add(
            Technology(
                application_id=app.id,
                category="language-or-platform",
                name="python",
                detection_source="pyproject.toml",
            )
        )
        db.flush()

        page = list_technologies(db=db, _=None)

        assert page.items[0]["name"] == "python"
        assert page.items[0]["application_name"] == "demo"
        assert page.items[0]["repository_name"] == "demo"


def test_list_sboms_filters_active_and_counts_components() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        active = Sbom(
            application_id=app.id,
            scan_id=scan.id,
            sbom_digest="digest-active",
            storage_key="active.json",
            active=True,
        )
        inactive = Sbom(
            application_id=app.id,
            scan_id=scan.id,
            sbom_digest="digest-inactive",
            storage_key="inactive.json",
            active=False,
        )
        component_a = Component(purl="pkg:pypi/a@1", ecosystem="pypi", name="a", version="1")
        component_b = Component(purl="pkg:pypi/b@1", ecosystem="pypi", name="b", version="1")
        db.add_all([active, inactive, component_a, component_b])
        db.flush()
        db.add_all(
            [
                SbomComponent(sbom_id=active.id, component_id=component_a.id),
                SbomComponent(sbom_id=active.id, component_id=component_b.id),
                SbomComponent(sbom_id=inactive.id, component_id=component_a.id),
            ]
        )
        db.flush()

        page = list_sboms(active=True, db=db, _=None)

        assert len(page.items) == 1
        assert page.items[0]["id"] == str(active.id)
        assert page.items[0]["component_count"] == 2


def test_list_components_searches_and_returns_active_application_usage() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        component = Component(
            purl="pkg:pypi/fastapi@0.111.0",
            ecosystem="pypi",
            name="fastapi",
            version="0.111.0",
        )
        sbom = Sbom(
            application_id=app.id,
            scan_id=scan.id,
            sbom_digest="digest",
            storage_key="sbom.json",
            active=True,
        )
        db.add_all([component, sbom])
        db.flush()
        db.add(SbomComponent(sbom_id=sbom.id, component_id=component.id))
        db.flush()

        page = list_components(name="fast", ecosystem="pypi", db=db, _=None)
        usage = list_component_applications(component.id, db=db, _=None)

        assert page.items[0]["purl"] == "pkg:pypi/fastapi@0.111.0"
        assert page.items[0]["application_count"] == 1
        assert page.items[0]["applications"][0]["application_name"] == "demo"
        assert usage[0].application_id == app.id


def test_list_vulnerabilities_filters_and_counts_open_impact() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        open_finding = create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        create_finding(db, app, severity=Severity.critical, status=FindingStatus.resolved, risk_score=9.1)
        vulnerability = db.get(Vulnerability, open_finding.vulnerability_id)

        page = list_vulnerabilities(external_id=vulnerability.external_id, severity=Severity.critical, db=db, _=None)

        assert page.items[0]["external_id"] == vulnerability.external_id
        assert page.items[0]["open_finding_count"] == 1
        assert page.items[0]["affected_application_count"] == 1


def test_list_remediation_actions_returns_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="queued",
            provider="github",
            metadata_json={},
        )
        db.add(action)
        db.flush()

        page = list_remediation_actions(status="queued", action_type="github_issue", db=db, _=None)

        assert page.items[0]["id"] == str(action.id)
        assert page.items[0]["finding_severity"] == "high"
        assert page.items[0]["application_name"] == "demo"


def test_list_vex_statements_filters_expired_status_and_returns_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        expired = VexStatement(
            finding_id=finding.id,
            status=VexStatus.not_affected,
            justification="component is not reachable",
            approved_by="security",
            review_date=now_utc() - timedelta(days=1),
        )
        upcoming = VexStatement(
            finding_id=finding.id,
            status=VexStatus.under_investigation,
            justification="review pending",
            approved_by="security",
            review_date=now_utc() + timedelta(days=7),
        )
        db.add_all([expired, upcoming])
        db.flush()

        page = list_vex_statements(
            expired=True,
            status=VexStatus.not_affected,
            finding_id=finding.id,
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(expired.id)]
        assert page.items[0]["application_name"] == app.name
        assert page.items[0]["repository_name"] == repo.name
        assert page.items[0]["vulnerability_external_id"] == "high-open"
        assert page.items[0]["expired"] is True


def test_list_scan_health_returns_failed_partial_and_stale_applications() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        failed_app = create_application(db, repo, "failed")
        partial_app = create_application(db, repo, "partial")
        stale_app = create_application(db, repo, "stale")
        healthy_app = create_application(db, repo, "healthy")
        db.add_all(
            [
                Scan(
                    application_id=failed_app.id,
                    status=ScanStatus.failed,
                    error_message="scanner crashed",
                    created_at=now_utc(),
                ),
                Scan(
                    application_id=partial_app.id,
                    status=ScanStatus.partially_succeeded,
                    result_summary={"scanner_failures": [{"scanner": "trivy"}]},
                    created_at=now_utc(),
                ),
                Scan(
                    application_id=stale_app.id,
                    status=ScanStatus.succeeded,
                    created_at=now_utc() - timedelta(days=31),
                ),
                Scan(application_id=healthy_app.id, status=ScanStatus.succeeded, created_at=now_utc()),
            ]
        )
        db.flush()

        page = list_scan_health(db=db, _=None)

        by_name = {item["application_name"]: item for item in page.items}
        assert set(by_name) == {"failed", "partial", "stale"}
        assert by_name["failed"]["latest_scan_error_message"] == "scanner crashed"
        assert by_name["partial"]["scanner_failures"] == [{"scanner": "trivy"}]
        assert by_name["stale"]["stale"] is True


def test_list_sbom_coverage_reports_missing_and_component_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        covered_app = create_application(db, repo, "covered")
        missing_app = create_application(db, repo, "missing")
        scan = Scan(application_id=covered_app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        sbom = Sbom(
            application_id=covered_app.id,
            scan_id=scan.id,
            sbom_digest="coverage-digest",
            storage_key="coverage.json",
            active=True,
            sbom_kind="source",
        )
        component = Component(purl="pkg:pypi/coverage@1", ecosystem="pypi", name="coverage", version="1")
        db.add_all([sbom, component])
        db.flush()
        db.add(SbomComponent(sbom_id=sbom.id, component_id=component.id))
        db.flush()

        all_page = list_sbom_coverage(db=db, _=None)
        missing_page = list_sbom_coverage(missing=True, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_name = {item["application_name"]: item for item in all_page.items}
        assert by_name["covered"]["has_active_source_sbom"] is True
        assert by_name["covered"]["component_count"] == 1
        assert [item["application_name"] for item in missing_page.items] == [missing_app.name]
        assert summary.missing_active_sbom == 1
        assert summary.sbom_coverage_percent == 50.0


def test_list_notifications_filters_and_returns_finding_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)
        matching = Notification(
            channel="slack",
            severity=Severity.critical,
            subject="Critical vulnerability detected",
            body="body",
            status="failed",
            metadata_json={"finding_id": str(finding.id)},
        )
        skipped = Notification(
            channel="discord",
            severity=Severity.high,
            subject="High vulnerability detected",
            body="body",
            status="queued",
            metadata_json={},
        )
        db.add_all([matching, skipped])
        db.flush()

        page = list_notifications(
            status="failed",
            channel="slack",
            severity=Severity.critical,
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(matching.id)]
        assert page.items[0]["finding_id"] == str(finding.id)
        assert page.items[0]["application_name"] == app.name
        assert page.items[0]["vulnerability_external_id"] == "critical-open"


def test_list_application_maintenance_candidates_reports_reasons() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        missing_owner = create_application(db, repo, "missing-owner")
        unsupported = create_application(db, repo, "unsupported")
        unsupported.owner = "team"
        unsupported.support_status = "unsupported"
        deprecated = create_application(db, repo, "deprecated")
        deprecated.owner = "team"
        deprecated.lifecycle = Lifecycle.deprecated
        stale = create_application(db, repo, "stale")
        stale.owner = "team"
        healthy = create_application(db, repo, "healthy")
        healthy.owner = "team"
        db.add_all(
            [
                Scan(application_id=missing_owner.id, status=ScanStatus.succeeded, created_at=now_utc()),
                Scan(application_id=unsupported.id, status=ScanStatus.succeeded, created_at=now_utc()),
                Scan(application_id=deprecated.id, status=ScanStatus.succeeded, created_at=now_utc()),
                Scan(
                    application_id=stale.id,
                    status=ScanStatus.succeeded,
                    created_at=now_utc() - timedelta(days=31),
                ),
                Scan(application_id=healthy.id, status=ScanStatus.succeeded, created_at=now_utc()),
            ]
        )
        db.flush()

        page = list_application_maintenance_candidates(db=db, _=None)

        by_name = {item["application_name"]: item for item in page.items}
        assert set(by_name) == {"deprecated", "missing-owner", "stale", "unsupported"}
        assert by_name["missing-owner"]["reasons"] == ["missing_owner"]
        assert by_name["unsupported"]["reasons"] == ["unsupported"]
        assert by_name["deprecated"]["reasons"] == ["deprecated"]
        assert by_name["stale"]["reasons"] == ["stale_scan"]


def test_list_remediation_candidates_excludes_findings_with_open_issue_action() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        candidate = create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        with_issue = create_finding(db, app, severity=Severity.high, risk_score=8.2)
        db.add(
            RemediationAction(
                finding_id=with_issue.id,
                action_type="github_issue",
                status="created",
                provider="github",
                metadata_json={"finding_id": str(with_issue.id)},
            )
        )
        db.flush()

        page = list_remediation_candidates(db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(candidate.id)]
        assert page.items[0]["application_name"] == app.name
        assert page.items[0]["vulnerability_external_id"] == "critical-open"
        assert page.items[0]["fixed_version"] == "1.0.1"


def test_list_github_issue_actions_filters_and_returns_errors() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)
        matching = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="close_failed",
            provider="github",
            provider_id="42",
            url="https://github.com/local/demo/issues/42",
            metadata_json={"close_error": "github unavailable"},
        )
        skipped = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="queued",
            provider="watchtower",
            metadata_json={},
        )
        db.add_all([matching, skipped])
        db.flush()

        page = list_github_issue_actions(
            status="close_failed",
            severity=Severity.critical,
            finding_id=finding.id,
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(matching.id)]
        assert page.items[0]["provider_id"] == "42"
        assert page.items[0]["close_error"] == "github unavailable"
        assert page.items[0]["application_name"] == app.name


def test_list_remediation_validations_filters_metadata_status() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        scan = Scan(application_id=app.id, status=ScanStatus.failed)
        db.add(scan)
        db.flush()
        failed = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            metadata_json={
                "validation_status": "failed",
                "validation_scan_id": str(scan.id),
                "validation_scan_status": "failed",
                "validation_error": "syft missing",
            },
        )
        pending = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="queued",
            provider="watchtower",
            metadata_json={},
        )
        db.add_all([failed, pending])
        db.flush()

        page = list_remediation_validations(
            validation_status="failed",
            action_type="github_issue",
            severity=Severity.high,
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(failed.id)]
        assert page.items[0]["validation_scan_id"] == str(scan.id)
        assert page.items[0]["validation_scan_status"] == "failed"
        assert page.items[0]["validation_error"] == "syft missing"


def test_list_issue_closures_reports_close_states() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        not_requested = create_finding(db, app, severity=Severity.critical, status=FindingStatus.resolved)
        pending = create_finding(db, app, severity=Severity.high, status=FindingStatus.resolved)
        close_failed = create_finding(db, app, severity=Severity.medium, status=FindingStatus.resolved)
        closed = create_finding(db, app, severity=Severity.low, status=FindingStatus.resolved)
        db.add_all(
            [
                RemediationAction(
                    finding_id=pending.id,
                    action_type="github_issue",
                    status="created",
                    provider="github",
                    provider_id="10",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=close_failed.id,
                    action_type="github_issue",
                    status="close_failed",
                    provider="github",
                    provider_id="11",
                    metadata_json={"close_error": "rate limited"},
                ),
                RemediationAction(
                    finding_id=closed.id,
                    action_type="github_issue",
                    status="closed",
                    provider="github",
                    provider_id="12",
                    metadata_json={"github_issue_closed_at": "2026-07-15T00:00:00+00:00"},
                ),
            ]
        )
        db.flush()

        page = list_issue_closures(db=db, _=None)

        by_finding = {item["finding_id"]: item for item in page.items}
        assert by_finding[str(not_requested.id)]["close_state"] == "not_requested"
        assert by_finding[str(pending.id)]["close_state"] == "pending_close"
        assert by_finding[str(close_failed.id)]["close_state"] == "close_failed"
        assert by_finding[str(close_failed.id)]["close_error"] == "rate limited"
        assert by_finding[str(closed.id)]["close_state"] == "closed"


def test_list_job_health_reports_unhealthy_jobs_and_summary_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        db.add_all(
            [
                Job(
                    job_type=JobType.scan,
                    status=JobStatus.failed,
                    repository_id=repo.id,
                    application_id=app.id,
                    last_error="clone failed",
                ),
                Job(
                    job_type=JobType.notification,
                    status=JobStatus.running,
                    started_at=now_utc() - timedelta(hours=2),
                ),
                Job(
                    job_type=JobType.issue_create,
                    status=JobStatus.queued,
                    run_after=now_utc() - timedelta(hours=2),
                ),
                Job(
                    job_type=JobType.repository_sync,
                    status=JobStatus.queued,
                    run_after=now_utc() + timedelta(minutes=5),
                ),
            ]
        )
        db.flush()

        page = list_job_health(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        reasons = {item["health_reason"] for item in page.items}
        assert reasons == {"failed", "stale_running", "overdue_queued"}
        failed = next(item for item in page.items if item["health_reason"] == "failed")
        assert failed["repository_name"] == repo.name
        assert failed["application_name"] == app.name
        assert summary.unhealthy_jobs == 3


def test_list_artifacts_returns_scan_artifact_context_and_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={
                "artifacts": {
                    "source_sbom": {"storage_key": "source.cdx.json", "digest": "sha-source"},
                    "osv": {"storage_key": "osv.json", "digest": "sha-osv"},
                }
            },
        )
        db.add(scan)
        db.flush()
        sbom = Sbom(
            application_id=app.id,
            scan_id=scan.id,
            sbom_digest="sha-source",
            storage_key="source.cdx.json",
            active=True,
        )
        db.add(sbom)
        db.flush()

        page = list_artifacts(artifact_type="source_sbom", repository_id=repo.id, db=db, _=None)

        assert len(page.items) == 1
        assert page.items[0]["artifact_type"] == "source_sbom"
        assert page.items[0]["storage_key"] == "source.cdx.json"
        assert page.items[0]["digest"] == "sha-source"
        assert page.items[0]["sbom_id"] == str(sbom.id)
        assert page.items[0]["application_name"] == app.name


def test_list_ai_fix_actions_filters_and_returns_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        matching = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="queued",
            provider="watchtower",
            fixed_version="1.0.1",
            metadata_json={"fixed_version": "1.0.1"},
        )
        skipped = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="queued",
            provider="github",
            metadata_json={},
        )
        db.add_all([matching, skipped])
        db.flush()

        page = list_ai_fix_actions(
            status="queued",
            severity=Severity.high,
            application_id=app.id,
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(matching.id)]
        assert page.items[0]["application_name"] == app.name
        assert page.items[0]["requested_fixed_version"] == "1.0.1"
        assert page.items[0]["vulnerability_external_id"] == "high-open"


def test_list_ai_fix_candidates_excludes_existing_open_ai_fix_action() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        candidate = create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        with_action = create_finding(db, app, severity=Severity.high, risk_score=8.0)
        db.add(
            RemediationAction(
                finding_id=with_action.id,
                action_type="ai_fix",
                status="queued",
                provider="watchtower",
                metadata_json={"finding_id": str(with_action.id)},
            )
        )
        db.flush()

        page = list_ai_fix_candidates(db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(candidate.id)]
        assert page.items[0]["fixed_version"] == "1.0.1"
        assert page.items[0]["repository_name"] == repo.name


def test_list_auto_merge_eligibility_uses_policy_inputs() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        app.auto_merge_enabled = True
        app.production = False
        app.criticality = "medium"
        finding = create_finding(db, app, severity=Severity.high)
        eligible = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            metadata_json={
                "update_kind": "patch",
                "ci_passed": True,
                "validation_status": "succeeded",
                "touches_forbidden_path": False,
            },
        )
        db.add(eligible)
        db.flush()

        page = list_auto_merge_eligibility(db=db, _=None)

        assert page.items[0]["action_id"] == str(eligible.id)
        assert page.items[0]["allowed"] is True
        assert page.items[0]["reason"] == "eligible"
        assert page.items[0]["tier_allows"] is True
        assert page.items[0]["validation_scan_resolved"] is True


def test_list_auto_merge_eligibility_blocks_forbidden_path() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        app.auto_merge_enabled = True
        finding = create_finding(db, app, severity=Severity.high)
        action = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            metadata_json={
                "update_kind": "minor",
                "ci_passed": True,
                "validation_status": "succeeded",
                "tier_allows": True,
                "touches_forbidden_path": True,
            },
        )
        db.add(action)
        db.flush()

        page = list_auto_merge_eligibility(db=db, _=None)

        assert page.items[0]["allowed"] is False
        assert page.items[0]["reason"] == "change touches a forbidden path"


def test_list_isolated_lane_returns_isolated_and_restricted_applications() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        isolated_repo = create_repository(db, "isolated")
        isolated_repo.provider = RepositoryProvider.isolated
        isolated_repo.source_classification = SourceClassification.isolated
        restricted_repo = create_repository(db, "restricted")
        restricted_repo.source_classification = SourceClassification.restricted
        regular_repo = create_repository(db, "regular")
        isolated_app = create_application(db, isolated_repo, "isolated-app")
        restricted_app = create_application(db, restricted_repo, "restricted-app")
        regular_app = create_application(db, regular_repo, "regular-app")
        scan = Scan(application_id=isolated_app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        db.add(
            Sbom(
                application_id=isolated_app.id,
                scan_id=scan.id,
                sbom_digest="isolated-sbom",
                storage_key="isolated.json",
                active=True,
                sbom_kind="source",
            )
        )
        db.flush()

        page = list_isolated_lane(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_name = {item["application_name"]: item for item in page.items}
        assert set(by_name) == {isolated_app.name, restricted_app.name}
        assert regular_app.name not in by_name
        assert by_name[isolated_app.name]["latest_scan_status"] == "succeeded"
        assert by_name[isolated_app.name]["active_source_sbom_count"] == 1
        assert summary.isolated_applications == 2


def test_list_sla_findings_reports_breaches_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        breached = create_finding(db, app, severity=Severity.critical, risk_score=9.8)
        breached.created_at = now_utc() - timedelta(days=8)
        within = create_finding(db, app, severity=Severity.high, risk_score=8.0)
        within.created_at = now_utc() - timedelta(days=3)
        resolved = create_finding(db, app, severity=Severity.medium, status=FindingStatus.resolved)
        resolved.created_at = now_utc() - timedelta(days=60)
        db.flush()

        page = list_sla_findings(breached=True, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(breached.id)]
        assert page.items[0]["sla_days"] == 7
        assert page.items[0]["breached"] is True
        assert summary.sla_breached_findings == 1


def test_enqueue_github_issue_endpoint_queues_and_suppresses_duplicate() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)

        first = enqueue_github_issue_endpoint(finding.id, db=db, _=None)
        second = enqueue_github_issue_endpoint(finding.id, db=db, _=None)

        assert first["id"] == second["id"]
        assert first["status"] == "queued"
        assert len(list(db.scalars(select(RemediationAction)))) == 1


def test_enqueue_github_issue_endpoint_rejects_ineligible_finding() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.medium)

        with pytest.raises(HTTPException) as exc:
            enqueue_github_issue_endpoint(finding.id, db=db, _=None)

        assert exc.value.status_code == 409
