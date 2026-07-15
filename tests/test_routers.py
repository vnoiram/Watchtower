from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    AuditLog,
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
from api.app.routers.audit_logs import list_audit_logs
from api.app.routers.application_detection import list_application_detection
from api.app.routers.applications import list_applications
from api.app.routers.ai_fix import list_ai_fix_actions, list_ai_fix_candidates
from api.app.routers.audit import list_audit_review
from api.app.routers.artifacts import list_artifact_sbom_coverage, list_artifacts
from api.app.routers.auto_merge import list_auto_merge_eligibility
from api.app.routers.components import list_component_applications, list_components, list_license_review
from api.app.routers.dashboard import dashboard_summary
from api.app.routers.exceptions import list_exceptions
from api.app.routers.findings import list_findings
from api.app.routers.findings import enqueue_github_issue as enqueue_github_issue_endpoint
from api.app.routers.findings import list_resolution_candidates
from api.app.routers.governance import (
    list_auto_merge_scope,
    list_exposure_review,
    list_ownership_review,
    list_risk_acceptance_review,
    list_runtime_eol,
    quarterly_review,
)
from api.app.routers.integrations import github_integration_health, list_webhook_intake
from api.app.routers.isolated_lane import list_isolated_lane, list_isolated_safeguards
from api.app.routers.job_health import list_job_health
from api.app.routers.jobs import list_retry_candidates
from api.app.routers.kpis import efficiency_kpis, kpi_summary, quality_kpis
from api.app.routers.maintenance import list_application_maintenance_candidates
from api.app.routers.notifications import list_notification_slo, list_notifications
from api.app.routers.operations import (
    backup_readiness,
    daily_operations,
    list_failure_signals,
    list_manual_actions,
    operational_workload,
    operations_readiness,
    restore_readiness,
    scan_targets,
    worker_posture,
    weekly_review,
)
from api.app.routers.quality import list_duplicate_review, list_reopen_risk
from api.app.routers.remediation import (
    list_remediation_backlog,
    list_remediation_coverage,
    list_dependency_updates,
    list_github_issue_actions,
    list_issue_closures,
    list_remediation_prs,
    list_remediation_rescans,
    list_remediation_candidates,
    list_remediation_validations,
    list_resolution_verification,
)
from api.app.routers.remediation_actions import list_remediation_actions
from api.app.routers.repository_sync import list_repository_sync
from api.app.routers.rollout import (
    list_application_readiness,
    list_repository_rollout,
    list_rollout_gaps,
    rollout_baseline,
)
from api.app.routers.scan_health import list_scan_health
from api.app.routers.scanner_inventory import list_scanner_inventory
from api.app.routers.scanners import list_scanner_failures
from api.app.routers.scanner_versions import list_scanner_versions
from api.app.routers.scheduled_scan_coverage import list_scheduled_scan_coverage
from api.app.routers.security import (
    data_protection,
    list_exploit_intel,
    list_secrets_review,
    list_security_findings,
    rbac_review,
)
from api.app.routers.sbom_coverage import list_sbom_coverage
from api.app.routers.sboms import list_sboms
from api.app.routers.sla import list_sla_findings
from api.app.routers.storage import list_storage_cleanup_candidates, retention_review
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


def test_list_retry_candidates_returns_failed_jobs_with_remaining_attempts() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        retryable = Job(
            job_type=JobType.scan,
            status=JobStatus.failed,
            repository_id=repo.id,
            application_id=app.id,
            attempts=1,
            max_attempts=3,
            last_error="scanner timeout",
        )
        exhausted = Job(
            job_type=JobType.notification,
            status=JobStatus.failed,
            attempts=3,
            max_attempts=3,
        )
        succeeded = Job(job_type=JobType.repository_sync, status=JobStatus.succeeded)
        db.add_all([retryable, exhausted, succeeded])
        db.flush()

        page = list_retry_candidates(db=db, _=None)

        assert [item["id"] for item in page.items] == [str(retryable.id)]
        assert page.items[0]["application_name"] == app.name
        assert page.items[0]["repository_name"] == repo.name
        assert page.items[0]["last_error"] == "scanner timeout"


def test_list_scanner_inventory_filters_failed_scanner_runs() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        failed = Scan(
            application_id=app.id,
            status=ScanStatus.partially_succeeded,
            tool="syft",
            tool_version="1.0.0",
            result_summary={"scanner_failures": [{"scanner": "osv", "error": "timeout"}]},
        )
        healthy = Scan(application_id=app.id, status=ScanStatus.succeeded, tool="syft")
        db.add_all([failed, healthy])
        db.flush()

        page = list_scanner_inventory(tool="syft", failed_only=True, db=db, _=None)

        assert [item["scan_id"] for item in page.items] == [str(failed.id)]
        assert page.items[0]["scanner_failure"] is True
        assert page.items[0]["scanner_failures"] == [{"scanner": "osv", "error": "timeout"}]
        assert page.items[0]["application_name"] == app.name


def test_list_exceptions_returns_finding_and_vex_review_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        accepted = create_finding(db, app, severity=Severity.high, status=FindingStatus.accepted_risk)
        false_positive = create_finding(db, app, severity=Severity.medium, status=FindingStatus.false_positive)
        vex_finding = create_finding(db, app, severity=Severity.low)
        vex = VexStatement(
            finding_id=vex_finding.id,
            status=VexStatus.not_affected,
            justification="not reachable",
            approved_by="security",
            review_date=now_utc() - timedelta(days=1),
        )
        db.add(vex)
        db.flush()

        all_page = list_exceptions(db=db, _=None)
        expired_page = list_exceptions(exception_type="vex", expired=True, db=db, _=None)
        severity_page = list_exceptions(severity=Severity.medium, db=db, _=None)

        assert {item["finding_id"] for item in all_page.items} == {
            str(accepted.id),
            str(false_positive.id),
            str(vex_finding.id),
        }
        assert [item["finding_id"] for item in expired_page.items] == [str(vex_finding.id)]
        assert expired_page.items[0]["expired"] is True
        assert expired_page.items[0]["application_name"] == app.name
        assert expired_page.items[0]["repository_name"] == repo.name
        assert [item["finding_id"] for item in severity_page.items] == [str(false_positive.id)]


def test_list_storage_cleanup_candidates_reports_inactive_old_and_failed_artifacts() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        inactive_scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        old_scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=91),
            result_summary={"artifacts": {"osv": {"storage_key": "old-osv.json", "digest": "old-digest"}}},
        )
        failed_scan = Scan(
            application_id=app.id,
            status=ScanStatus.failed,
            result_summary={"sbom_stored": False},
        )
        db.add_all([inactive_scan, old_scan, failed_scan])
        db.flush()
        inactive = Sbom(
            application_id=app.id,
            scan_id=inactive_scan.id,
            sbom_digest="inactive-cleanup",
            storage_key="inactive-cleanup.json",
            active=False,
        )
        db.add(inactive)
        db.flush()

        page = list_storage_cleanup_candidates(db=db, _=None)

        by_reason = {item["reason"]: item for item in page.items}
        assert set(by_reason) == {"inactive_sbom", "old_scan_artifact", "failed_scan_without_sbom"}
        assert by_reason["inactive_sbom"]["storage_key"] == "inactive-cleanup.json"
        assert by_reason["inactive_sbom"]["sbom_id"] == str(inactive.id)
        assert by_reason["old_scan_artifact"]["storage_key"] == "old-osv.json"
        assert by_reason["old_scan_artifact"]["digest"] == "old-digest"
        assert by_reason["failed_scan_without_sbom"]["scan_id"] == str(failed_scan.id)


def test_operational_workload_reports_manual_queues_and_dashboard_total() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)
        db.add_all(
            [
                Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.succeeded),
                AuditLog(
                    actor="api-token",
                    role="operator",
                    action="job.create",
                    resource_type="job",
                    resource_id="job-1",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="ai_fix",
                    status="failed",
                    provider="watchtower",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="github_issue",
                    status="close_failed",
                    provider="github",
                    metadata_json={},
                ),
            ]
        )
        db.flush()

        rows = operational_workload(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_item = {row.item: row for row in rows}
        assert by_item["open_findings"].count == 1
        assert by_item["manual_scans"].count == 1
        assert by_item["manual_jobs"].count == 1
        assert by_item["failed_remediation_actions"].count == 1
        assert by_item["close_failed_issue_actions"].count == 1
        assert by_item["close_failed_issue_actions"].status == "fail"
        assert summary.manual_workload_items == 5


def test_list_repository_sync_reports_stale_and_failed_sync_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        stale_repo = create_repository(db, "stale-sync")
        stale_repo.last_synced_at = now_utc() - timedelta(days=31)
        stale_repo.archived = True
        healthy_repo = create_repository(db, "healthy-sync")
        healthy_repo.last_synced_at = now_utc()
        create_repository(db, "never-sync")
        failed_job = Job(
            job_type=JobType.repository_sync,
            status=JobStatus.failed,
            repository_id=stale_repo.id,
            last_error="github unavailable",
        )
        db.add(failed_job)
        db.flush()

        page = list_repository_sync(stale=True, provider=RepositoryProvider.github, db=db, _=None)

        by_name = {item["repository_name"]: item for item in page.items}
        assert set(by_name) == {"never-sync", "stale-sync"}
        assert "stale_sync" in by_name["stale-sync"]["reasons"]
        assert "sync_job_failed" in by_name["stale-sync"]["reasons"]
        assert "archived" in by_name["stale-sync"]["reasons"]
        assert by_name["stale-sync"]["latest_sync_job_status"] == "failed"
        assert by_name["never-sync"]["reasons"] == ["never_synced"]
        assert healthy_repo.name not in by_name


def test_list_application_detection_reports_missing_unknown_and_technology_gaps() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        empty_repo = create_repository(db, "empty")
        app_repo = create_repository(db, "app-repo")
        unknown_app = create_application(db, app_repo, "unknown-app")
        unknown_app.application_type = ApplicationType.unknown
        typed_app = create_application(db, app_repo, "typed-app")
        typed_app.application_type = ApplicationType.api
        db.add(
            Technology(
                application_id=typed_app.id,
                category="language-or-platform",
                name="python",
                detection_source="pyproject.toml",
            )
        )
        db.flush()

        page = list_application_detection(db=db, _=None)
        missing_technology_page = list_application_detection(issue_type="missing_technology", db=db, _=None)

        issues = {(item["issue_type"], item["repository_name"], item["application_name"]) for item in page.items}
        assert ("missing_application", empty_repo.name, None) in issues
        assert ("unknown_application_type", app_repo.name, unknown_app.name) in issues
        assert ("missing_technology", app_repo.name, unknown_app.name) in issues
        assert [item["application_name"] for item in missing_technology_page.items] == [unknown_app.name]


def test_list_scheduled_scan_coverage_reports_missing_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        covered = create_application(db, repo, "covered-schedule")
        missing = create_application(db, repo, "missing-schedule")
        manual_only = create_application(db, repo, "manual-only")
        db.add_all(
            [
                Scan(
                    application_id=covered.id,
                    trigger_type=TriggerType.schedule,
                    status=ScanStatus.succeeded,
                    created_at=now_utc(),
                ),
                Scan(
                    application_id=missing.id,
                    trigger_type=TriggerType.schedule,
                    status=ScanStatus.succeeded,
                    created_at=now_utc() - timedelta(days=2),
                ),
                Scan(
                    application_id=manual_only.id,
                    trigger_type=TriggerType.manual,
                    status=ScanStatus.succeeded,
                    created_at=now_utc(),
                ),
            ]
        )
        db.flush()

        page = list_scheduled_scan_coverage(missing=True, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_name = {item["application_name"]: item for item in page.items}
        assert set(by_name) == {"manual-only", "missing-schedule"}
        assert by_name["manual-only"]["manual_only"] is True
        assert by_name["missing-schedule"]["latest_scheduled_scan_status"] == "succeeded"
        assert covered.name not in by_name
        assert summary.missing_scheduled_scans == 2


def test_list_resolution_candidates_reports_findings_missing_from_latest_successful_scan() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        older_scan = Scan(application_id=app.id, status=ScanStatus.succeeded, created_at=now_utc() - timedelta(days=2))
        latest_scan = Scan(application_id=app.id, status=ScanStatus.succeeded, created_at=now_utc())
        db.add_all([older_scan, latest_scan])
        db.flush()
        candidate = create_finding(db, app, severity=Severity.high, status=FindingStatus.open)
        candidate.last_seen_scan_id = older_scan.id
        still_present = create_finding(db, app, severity=Severity.critical, status=FindingStatus.open)
        still_present.last_seen_scan_id = latest_scan.id
        resolved = create_finding(db, app, severity=Severity.medium, status=FindingStatus.resolved)
        resolved.last_seen_scan_id = older_scan.id
        db.flush()

        page = list_resolution_candidates(severity=Severity.high, db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(candidate.id)]
        assert page.items[0]["latest_successful_scan_id"] == str(latest_scan.id)
        assert page.items[0]["last_seen_scan_id"] == str(older_scan.id)
        assert page.items[0]["application_name"] == app.name
        assert str(still_present.id) not in {item["finding_id"] for item in page.items}
        assert str(resolved.id) not in {item["finding_id"] for item in page.items}


def test_backup_readiness_reports_storage_artifact_and_cleanup_state() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        with_artifact = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={"artifacts": {"source_sbom": {"storage_key": "source.json"}}},
        )
        without_artifact = Scan(application_id=app.id, status=ScanStatus.succeeded)
        db.add_all([with_artifact, without_artifact])
        db.flush()
        active = Sbom(
            application_id=app.id,
            scan_id=with_artifact.id,
            sbom_digest="active-backup",
            storage_key="active-backup.json",
            active=True,
            sbom_kind="source",
        )
        inactive = Sbom(
            application_id=app.id,
            scan_id=without_artifact.id,
            sbom_digest="inactive-backup",
            storage_key="inactive-backup.json",
            active=False,
            sbom_kind="source",
        )
        db.add_all([active, inactive])
        db.flush()
        settings = Settings(minio_endpoint="", minio_access_key="", minio_secret_key="", minio_bucket="")

        rows = backup_readiness(db=db, settings=settings, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["object_storage"].status == "fail"
        assert by_check["sbom_storage_keys"].status == "ok"
        assert by_check["source_sbom_artifacts"].status == "warn"
        assert by_check["source_sbom_artifacts"].count == 1
        assert by_check["cleanup_backlog"].status == "warn"
        assert by_check["cleanup_backlog"].count == 1


def test_list_notification_slo_reports_breaches_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        breached = create_finding(db, app, severity=Severity.critical)
        breached.created_at = now_utc() - timedelta(hours=2)
        notified = create_finding(db, app, severity=Severity.high)
        notified.created_at = now_utc() - timedelta(hours=25)
        db.add(
            Notification(
                channel="slack",
                severity=Severity.high,
                subject="High vulnerability detected",
                body="body",
                status="sent",
                sent_at=notified.created_at + timedelta(hours=23),
                metadata_json={"finding_id": str(notified.id)},
            )
        )
        db.flush()

        page = list_notification_slo(breached=True, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(breached.id)]
        assert page.items[0]["severity"] == "critical"
        assert page.items[0]["breached"] is True
        assert page.items[0]["application_name"] == app.name
        assert summary.notification_slo_breaches == 1


def test_list_remediation_prs_reports_ci_and_pr_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        pr_action = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            branch="fix/high",
            metadata_json={"pull_request_url": "https://github.com/local/demo/pull/7", "ci_passed": False},
        )
        skipped = RemediationAction(
            finding_id=finding.id,
            action_type="ai_fix",
            status="queued",
            provider="watchtower",
            metadata_json={},
        )
        db.add_all([pr_action, skipped])
        db.flush()

        page = list_remediation_prs(severity=Severity.high, db=db, _=None)

        assert [item["action_id"] for item in page.items] == [str(pr_action.id)]
        assert page.items[0]["url"] == "https://github.com/local/demo/pull/7"
        assert page.items[0]["ci_passed"] is False
        assert page.items[0]["application_name"] == app.name


def test_list_remediation_backlog_reports_stale_and_failed_items() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        stale_finding = create_finding(db, app, severity=Severity.high)
        failed_finding = create_finding(db, app, severity=Severity.critical)
        stale = RemediationAction(
            finding_id=stale_finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            metadata_json={},
            updated_at=now_utc() - timedelta(days=8),
        )
        failed = RemediationAction(
            finding_id=failed_finding.id,
            action_type="ai_fix",
            status="failed",
            provider="watchtower",
            metadata_json={"error": "patch failed"},
        )
        healthy = RemediationAction(
            finding_id=stale_finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            metadata_json={},
        )
        db.add_all([stale, failed, healthy])
        db.flush()

        page = list_remediation_backlog(db=db, _=None)
        high_page = list_remediation_backlog(severity=Severity.high, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_id = {item["action_id"]: item for item in page.items}
        assert set(by_id) == {str(stale.id), str(failed.id)}
        assert by_id[str(stale.id)]["reason"] == "stale_open"
        assert by_id[str(failed.id)]["reason"] == "failed"
        assert by_id[str(failed.id)]["detail"] == "patch failed"
        assert [item["action_id"] for item in high_page.items] == [str(stale.id)]
        assert summary.stale_remediation_items == 2


def test_list_remediation_rescans_reports_validation_and_missing_rescans() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        validated_app = create_application(db, repo, "validated-rescan")
        missing_app = create_application(db, repo, "missing-rescan")
        validated_finding = create_finding(db, validated_app, severity=Severity.high)
        missing_finding = create_finding(db, missing_app, severity=Severity.critical)
        validation_scan = Scan(
            application_id=validated_app.id,
            trigger_type=TriggerType.remediation_validation,
            status=ScanStatus.succeeded,
            created_at=now_utc(),
        )
        db.add(validation_scan)
        db.flush()
        validated_action = RemediationAction(
            finding_id=validated_finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            metadata_json={"validation_status": "succeeded", "validation_scan_id": str(validation_scan.id)},
            created_at=now_utc() - timedelta(hours=1),
        )
        missing_action = RemediationAction(
            finding_id=missing_finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            metadata_json={},
            created_at=now_utc() - timedelta(hours=1),
        )
        db.add_all([validated_action, missing_action])
        db.flush()

        all_page = list_remediation_rescans(db=db, _=None)
        missing_page = list_remediation_rescans(missing=True, db=db, _=None)

        by_action = {item["action_id"]: item for item in all_page.items}
        assert by_action[str(validated_action.id)]["validation_scan_id"] == str(validation_scan.id)
        assert by_action[str(validated_action.id)]["missing_rescan"] is False
        assert [item["action_id"] for item in missing_page.items] == [str(missing_action.id)]
        assert missing_page.items[0]["missing_rescan"] is True


def test_weekly_review_reports_operational_review_counts() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        medium = create_finding(db, app, severity=Severity.medium)
        create_finding(db, app, severity=Severity.low, status=FindingStatus.false_positive)
        vex_finding = create_finding(db, app, severity=Severity.high)
        db.add_all(
            [
                VexStatement(
                    finding_id=vex_finding.id,
                    status=VexStatus.not_affected,
                    justification="not reachable",
                    approved_by="security",
                    review_date=now_utc() - timedelta(days=1),
                ),
                VexStatement(
                    finding_id=medium.id,
                    status=VexStatus.under_investigation,
                    justification="review pending",
                    approved_by="security",
                    review_date=now_utc() + timedelta(days=3),
                ),
                RemediationAction(
                    finding_id=vex_finding.id,
                    action_type="ai_fix",
                    status="failed",
                    provider="watchtower",
                    metadata_json={},
                ),
                Scan(application_id=app.id, tool="syft", tool_version=None),
            ]
        )
        db.flush()

        rows = weekly_review(db=db, _=None)

        by_item = {row.item: row for row in rows}
        assert by_item["medium_findings"].count == 1
        assert by_item["expired_vex"].count == 1
        assert by_item["upcoming_vex"].count == 1
        assert by_item["false_positive"].count == 1
        assert by_item["auto_fix_failed"].count == 1
        assert by_item["scanner_version_missing"].count == 1
        assert by_item["stale_prs"].count == 1


def test_efficiency_kpis_reports_detection_notification_and_remediation_metrics() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(application_id=app.id, status=ScanStatus.succeeded, created_at=now_utc() - timedelta(hours=10))
        db.add(scan)
        db.flush()
        resolved = create_finding(db, app, severity=Severity.high, status=FindingStatus.resolved)
        resolved.first_seen_scan_id = scan.id
        resolved.created_at = now_utc() - timedelta(hours=8)
        resolved.resolved_at = now_utc() - timedelta(hours=2)
        open_finding = create_finding(db, app, severity=Severity.critical)
        open_finding.created_at = now_utc() - timedelta(hours=4)
        db.add_all(
            [
                Notification(
                    channel="slack",
                    severity=Severity.high,
                    subject="high",
                    body="body",
                    status="sent",
                    sent_at=resolved.created_at + timedelta(hours=1),
                    metadata_json={"finding_id": str(resolved.id)},
                ),
                RemediationAction(
                    finding_id=resolved.id,
                    action_type="github_issue",
                    status="created",
                    provider="github",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=resolved.id,
                    action_type="ai_fix",
                    status="created",
                    provider="watchtower",
                    metadata_json={"validation_status": "succeeded"},
                ),
            ]
        )
        db.flush()

        rows = efficiency_kpis(db=db, _=None)

        by_metric = {row.metric: row for row in rows}
        assert by_metric["mean_time_to_detect_hours"].value == 2.0
        assert by_metric["mean_time_to_notify_hours"].value == 1.0
        assert by_metric["mean_time_to_remediate_hours"].value == 6.0
        assert by_metric["issue_creation_rate_percent"].value == 50.0
        assert by_metric["auto_resolution_rate_percent"].value == 100.0
        assert open_finding.status == FindingStatus.open


def test_list_manual_actions_filters_and_updates_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        matching = AuditLog(
            actor="operator",
            role="operator",
            action="scan.create",
            resource_type="scan",
            resource_id="scan-1",
            metadata_json={},
            created_at=now_utc(),
        )
        dependency = AuditLog(
            actor="operator",
            role="operator",
            action="dependency.update",
            resource_type="repository",
            resource_id="repo-1",
            metadata_json={"mode": "manual"},
            created_at=now_utc(),
        )
        old = AuditLog(
            actor="operator",
            role="operator",
            action="job.create",
            resource_type="job",
            resource_id="job-1",
            metadata_json={},
            created_at=now_utc() - timedelta(days=40),
        )
        skipped = AuditLog(
            actor="system",
            role="admin",
            action="repository.sync",
            resource_type="repository",
            resource_id="repo-2",
            metadata_json={},
            created_at=now_utc(),
        )
        db.add_all([matching, dependency, old, skipped])
        db.flush()

        page = list_manual_actions(action="scan.create", actor="operator", db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        assert [item["id"] for item in page.items] == [str(matching.id)]
        assert page.items[0]["reason"] == "manual_scan"
        assert summary.manual_action_count == 2


def test_list_ownership_review_reports_owner_tier_and_lifecycle_issues() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        missing_owner = create_application(db, repo, "governance-missing-owner")
        unknown = create_application(db, repo, "governance-unknown")
        unknown.owner = "team"
        unknown.criticality = "unknown"
        production_low = create_application(db, repo, "governance-prod-low")
        production_low.owner = "team"
        production_low.production = True
        production_low.criticality = "low"
        unsupported = create_application(db, repo, "governance-unsupported")
        unsupported.owner = "team"
        unsupported.support_status = "unsupported"
        deprecated = create_application(db, repo, "governance-deprecated")
        deprecated.owner = "team"
        deprecated.lifecycle = Lifecycle.deprecated
        db.flush()

        page = list_ownership_review(db=db, _=None)
        missing_page = list_ownership_review(issue_type="missing_owner", db=db, _=None)

        issues = {(item["application_name"], item["issue_type"]) for item in page.items}
        assert (missing_owner.name, "missing_owner") in issues
        assert (unknown.name, "unknown_criticality") in issues
        assert (production_low.name, "production_low_criticality") in issues
        assert (unsupported.name, "unsupported") in issues
        assert (deprecated.name, "deprecated") in issues
        assert [item["application_name"] for item in missing_page.items] == [missing_owner.name]


def test_list_exposure_review_reports_public_risk_reasons_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        exposed = create_application(db, repo, "exposed-risk")
        exposed.internet_exposed = True
        exposed.production = True
        failed_scan = Scan(
            application_id=exposed.id,
            status=ScanStatus.failed,
            created_at=now_utc() - timedelta(days=31),
        )
        db.add(failed_scan)
        finding = create_finding(db, exposed, severity=Severity.critical)
        safe = create_application(db, repo, "exposed-safe")
        safe.internet_exposed = True
        safe_scan = Scan(application_id=safe.id, status=ScanStatus.succeeded, created_at=now_utc())
        db.add(safe_scan)
        db.flush()
        db.add(
            Sbom(
                application_id=safe.id,
                scan_id=safe_scan.id,
                sbom_digest="safe-exposure",
                storage_key="safe-exposure.json",
                active=True,
                sbom_kind="source",
            )
        )
        db.flush()

        page = list_exposure_review(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        assert [item["application_name"] for item in page.items] == [exposed.name]
        assert set(page.items[0]["reasons"]) == {
            "missing_active_source_sbom",
            "stale_scan",
            "latest_scan_failed",
            "open_critical_high",
        }
        assert page.items[0]["open_critical_high_count"] == 1
        assert page.items[0]["latest_scan_status"] == "failed"
        assert summary.exposure_review_items == 1
        assert finding.status == FindingStatus.open


def test_list_auto_merge_scope_reports_scope_risks_and_validation_state() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        risky = create_application(db, repo, "auto-merge-risky")
        risky.auto_merge_enabled = True
        risky.production = True
        risky.internet_exposed = True
        risky.criticality = "critical"
        safe = create_application(db, repo, "auto-merge-safe")
        safe.auto_merge_enabled = True
        safe.criticality = "medium"
        finding_risky = create_finding(db, risky, severity=Severity.high)
        finding_safe = create_finding(db, safe, severity=Severity.low)
        db.add_all(
            [
                RemediationAction(
                    finding_id=finding_risky.id,
                    action_type="ai_fix",
                    status="failed",
                    provider="watchtower",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=finding_safe.id,
                    action_type="ai_fix",
                    status="created",
                    provider="watchtower",
                    metadata_json={"validation_status": "succeeded"},
                    updated_at=now_utc(),
                ),
            ]
        )
        db.flush()

        page = list_auto_merge_scope(db=db, _=None)

        by_name = {item["application_name"]: item for item in page.items}
        assert set(by_name) == {risky.name, safe.name}
        assert set(by_name[risky.name]["reasons"]) == {
            "production",
            "high_criticality",
            "internet_exposed",
            "missing_recent_validation",
            "blocked_auto_merge_action",
        }
        assert by_name[risky.name]["blocked_action_count"] == 1
        assert by_name[safe.name]["recent_validation"] is True
        assert by_name[safe.name]["reasons"] == []


def test_data_protection_reports_configuration_without_secret_values() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={"artifacts": {"source_sbom": {"storage_key": "source.json"}}},
        )
        db.add(scan)
        db.flush()
        db.add(
            Sbom(
                application_id=app.id,
                scan_id=scan.id,
                sbom_digest="missing-storage-key",
                storage_key="",
                active=True,
                sbom_kind="source",
            )
        )
        db.flush()
        settings = Settings(
            github_token="secret-token",
            github_webhook_secret="webhook-secret",
            minio_secret_key="minio-secret",
        )

        rows = data_protection(db=db, settings=settings, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["object_storage"].configured is True
        assert by_check["github_secrets"].configured is True
        assert by_check["sbom_storage_keys"].configured is False
        assert by_check["sbom_storage_keys"].count == 1
        assert by_check["stored_artifacts"].count == 1
        rendered = " ".join(row.detail for row in rows)
        assert "secret-token" not in rendered
        assert "webhook-secret" not in rendered
        assert "minio-secret" not in rendered


def test_retention_review_reports_old_artifacts_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        old_scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=91),
            result_summary={"artifacts": {"osv": {"storage_key": "old-osv.json", "digest": "old"}}},
        )
        current_scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        old_log = AuditLog(
            actor="operator",
            role="operator",
            action="scan.create",
            resource_type="scan",
            resource_id="old",
            metadata_json={},
            created_at=now_utc() - timedelta(days=91),
        )
        db.add_all([old_scan, current_scan, old_log])
        db.flush()
        db.add(
            Sbom(
                application_id=app.id,
                scan_id=current_scan.id,
                sbom_digest="inactive-retention",
                storage_key="inactive-retention.json",
                active=False,
            )
        )
        db.flush()

        rows = retention_review(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_item = {row.item: row for row in rows}
        assert by_item["old_scan_artifacts"].count == 1
        assert by_item["inactive_sboms"].count == 1
        assert by_item["old_audit_logs"].count == 1
        assert by_item["cleanup_candidates"].count == 2
        assert summary.retention_review_items == 5


def test_list_artifact_sbom_coverage_reports_artifact_sbom_sources() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        covered = create_application(db, repo, "artifact-covered")
        missing = create_application(db, repo, "artifact-missing")
        scan = Scan(
            application_id=covered.id,
            status=ScanStatus.succeeded,
            result_summary={"artifacts": {"container_sbom": {"storage_key": "container.cdx.json"}}},
        )
        db.add(scan)
        db.flush()
        db.add(
            Sbom(
                application_id=covered.id,
                scan_id=scan.id,
                sbom_kind="container",
                sbom_digest="container-digest",
                storage_key="container.cdx.json",
                active=True,
            )
        )
        db.flush()

        all_page = list_artifact_sbom_coverage(db=db, _=None)
        missing_page = list_artifact_sbom_coverage(missing=True, db=db, _=None)

        by_name = {item["application_name"]: item for item in all_page.items}
        assert by_name[covered.name]["has_artifact_sbom"] is True
        assert by_name[covered.name]["artifact_types"] == ["container_sbom"]
        assert [item["application_name"] for item in missing_page.items] == [missing.name]


def test_list_license_review_reports_missing_unknown_and_copyleft_components() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        sbom = Sbom(application_id=app.id, scan_id=scan.id, sbom_digest="license-sbom", storage_key="license.json")
        missing = Component(purl="pkg:pypi/missing@1", ecosystem="pypi", name="missing", version="1")
        unknown = Component(purl="pkg:pypi/unknown@1", ecosystem="pypi", name="unknown", version="1", license="unknown")
        copyleft = Component(purl="pkg:npm/gpl@1", ecosystem="npm", name="gpl", version="1", license="GPL-3.0")
        permissive = Component(purl="pkg:pypi/mit@1", ecosystem="pypi", name="mit", version="1", license="MIT")
        db.add_all([sbom, missing, unknown, copyleft, permissive])
        db.flush()
        db.add_all(
            [
                SbomComponent(sbom_id=sbom.id, component_id=missing.id),
                SbomComponent(sbom_id=sbom.id, component_id=unknown.id),
                SbomComponent(sbom_id=sbom.id, component_id=copyleft.id),
                SbomComponent(sbom_id=sbom.id, component_id=permissive.id),
            ]
        )
        db.flush()

        page = list_license_review(db=db, _=None)
        npm_page = list_license_review(issue_type="copyleft_license", ecosystem="npm", db=db, _=None)

        issues = {(item["component_name"], item["issue_type"]) for item in page.items}
        assert issues == {
            ("gpl", "copyleft_license"),
            ("missing", "missing_license"),
            ("unknown", "unknown_license"),
        }
        assert [item["component_name"] for item in npm_page.items] == ["gpl"]
        assert npm_page.items[0]["application_name"] == app.name


def test_list_security_findings_extracts_scan_summary_findings() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={
                "secrets": [{"severity": "critical", "title": "AWS key", "path": ".env"}],
                "sast": [{"severity": "high", "rule_id": "sql-injection", "message": "unsafe query"}],
                "license_findings": [{"severity": "medium", "title": "GPL dependency"}],
                "security_findings": [{"severity": "low", "title": "generic hardening"}],
            },
        )
        db.add(scan)
        db.flush()

        page = list_security_findings(db=db, _=None)
        filtered = list_security_findings(finding_type="sast", severity="high", db=db, _=None)

        types = {item["finding_type"] for item in page.items}
        assert types == {"license", "sast", "secret", "security"}
        assert [item["title"] for item in filtered.items] == ["sql-injection"]
        assert filtered.items[0]["application_name"] == app.name
        assert filtered.items[0]["scan_status"] == "succeeded"


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


def test_list_duplicate_review_reports_notification_remediation_and_skipped_duplicates() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        db.add_all(
            [
                Notification(
                    channel="slack",
                    severity=Severity.high,
                    subject="duplicate",
                    body="body",
                    status="queued",
                    metadata_json={"finding_id": str(finding.id)},
                ),
                Notification(
                    channel="slack",
                    severity=Severity.high,
                    subject="duplicate",
                    body="body",
                    status="queued",
                    metadata_json={"finding_id": str(finding.id)},
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="ai_fix",
                    status="queued",
                    provider="watchtower",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="ai_fix",
                    status="created",
                    provider="watchtower",
                    metadata_json={},
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="github_issue",
                    status="skipped_duplicate",
                    provider="github",
                    metadata_json={},
                ),
            ]
        )
        db.flush()

        page = list_duplicate_review(db=db, _=None)
        notification_page = list_duplicate_review(duplicate_type="notification", db=db, _=None)

        by_type = {item["duplicate_type"]: item for item in page.items}
        assert set(by_type) == {"notification", "remediation_action", "skipped_duplicate"}
        assert by_type["notification"]["count"] == 2
        assert by_type["notification"]["application_name"] == app.name
        assert by_type["remediation_action"]["action_type"] == "ai_fix"
        assert [item["duplicate_type"] for item in notification_page.items] == ["notification"]


def test_list_reopen_risk_reports_seen_after_resolution_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        resolved = create_finding(db, app, severity=Severity.high, status=FindingStatus.resolved)
        resolved.resolved_at = now_utc() - timedelta(days=2)
        later_scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=1),
        )
        db.add(later_scan)
        db.flush()
        resolved.last_seen_scan_id = later_scan.id
        db.flush()

        page = list_reopen_risk(severity=Severity.high, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        assert [item["finding_id"] for item in page.items] == [str(resolved.id)]
        assert page.items[0]["reason"] == "seen_after_resolved"
        assert page.items[0]["last_seen_scan_id"] == str(later_scan.id)
        assert page.items[0]["application_name"] == app.name
        assert summary.reopen_risk_items == 1


def test_quality_kpis_reports_false_positive_vex_auto_merge_ci_and_reopen_rates() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        reopened = create_finding(db, app, severity=Severity.high, status=FindingStatus.resolved)
        reopened.resolved_at = now_utc() - timedelta(days=2)
        false_positive = create_finding(
            db,
            app,
            severity=Severity.low,
            status=FindingStatus.false_positive,
        )
        open_finding = create_finding(db, app, severity=Severity.critical)
        later_scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=1),
        )
        db.add(later_scan)
        db.flush()
        reopened.last_seen_scan_id = later_scan.id
        db.add_all(
            [
                VexStatement(
                    finding_id=open_finding.id,
                    status=VexStatus.not_affected,
                    justification="not reachable",
                    approved_by="security",
                    review_date=now_utc() - timedelta(days=1),
                ),
                VexStatement(
                    finding_id=reopened.id,
                    status=VexStatus.under_investigation,
                    justification="review pending",
                    approved_by="security",
                    review_date=now_utc() + timedelta(days=10),
                ),
                RemediationAction(
                    finding_id=open_finding.id,
                    action_type="ai_fix",
                    status="failed",
                    provider="watchtower",
                    metadata_json={"ci_passed": False},
                ),
                RemediationAction(
                    finding_id=reopened.id,
                    action_type="ai_fix",
                    status="created",
                    provider="watchtower",
                    metadata_json={"ci_passed": True},
                ),
            ]
        )
        db.flush()

        rows = quality_kpis(db=db, _=None)

        by_metric = {row.metric: row for row in rows}
        assert by_metric["false_positive_rate_percent"].value == 33.3
        assert by_metric["expired_vex_rate_percent"].value == 50.0
        assert by_metric["auto_merge_failure_rate_percent"].value == 50.0
        assert by_metric["pr_ci_failure_rate_percent"].value == 50.0
        assert by_metric["reopen_risk_count"].value == 1
        assert false_positive.status == FindingStatus.false_positive


def test_list_scanner_versions_reports_missing_stale_and_tool_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        db.add_all(
            [
                Scan(
                    application_id=app.id,
                    status=ScanStatus.succeeded,
                    tool="syft",
                    tool_version=None,
                    created_at=now_utc(),
                ),
                Scan(
                    application_id=app.id,
                    status=ScanStatus.succeeded,
                    tool="trivy",
                    tool_version="0.1.0",
                    created_at=now_utc() - timedelta(days=31),
                ),
            ]
        )
        db.flush()

        missing_page = list_scanner_versions(missing_version=True, db=db, _=None)
        stale_page = list_scanner_versions(stale=True, db=db, _=None)
        trivy_page = list_scanner_versions(tool="trivy", db=db, _=None)

        assert [item["tool"] for item in missing_page.items] == ["syft"]
        assert missing_page.items[0]["missing_version"] is True
        assert [item["tool"] for item in stale_page.items] == ["trivy"]
        assert stale_page.items[0]["stale"] is True
        assert trivy_page.items[0]["scan_count"] == 1
        assert trivy_page.items[0]["application_name"] == app.name


def test_list_runtime_eol_reports_missing_old_major_and_component_context() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(application_id=app.id, status=ScanStatus.succeeded)
        db.add(scan)
        db.flush()
        sbom = Sbom(
            application_id=app.id,
            scan_id=scan.id,
            sbom_digest="runtime-eol",
            storage_key="runtime-eol.json",
            active=True,
        )
        old_ruby = Component(purl="pkg:generic/ruby@2.7", ecosystem="runtime", name="ruby", version="2.7")
        current_java = Technology(
            application_id=app.id,
            category="language-or-platform",
            name="java",
            version="17",
            detection_source="build.gradle",
        )
        db.add_all(
            [
                sbom,
                old_ruby,
                current_java,
                Technology(
                    application_id=app.id,
                    category="language-or-platform",
                    name="python",
                    version="2.7",
                    detection_source="runtime.txt",
                ),
                Technology(
                    application_id=app.id,
                    category="runtime",
                    name="node",
                    version=None,
                    detection_source="package.json",
                ),
            ]
        )
        db.flush()
        db.add(SbomComponent(sbom_id=sbom.id, component_id=old_ruby.id))
        db.flush()

        page = list_runtime_eol(db=db, _=None)
        missing_page = list_runtime_eol(issue_type="missing_version", db=db, _=None)

        issues = {(item["source"], item["name"], item["issue_type"]) for item in page.items}
        assert ("technology", "python", "old_major") in issues
        assert ("technology", "node", "missing_version") in issues
        assert ("component", "ruby", "old_major") in issues
        assert ("technology", "java", "old_major") not in issues
        assert [item["name"] for item in missing_page.items] == ["node"]
        assert missing_page.items[0]["application_name"] == app.name


def test_list_audit_review_reports_manual_config_privileged_and_failure_events() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        manual = AuditLog(
            actor="operator",
            role="operator",
            action="scan.create",
            resource_type="scan",
            resource_id="scan-1",
            metadata_json={},
        )
        config = AuditLog(
            actor="admin",
            role="admin",
            action="repository.create",
            resource_type="repository",
            resource_id="repo-1",
            metadata_json={},
        )
        failure = AuditLog(
            actor="worker",
            role="admin",
            action="backup.restore",
            resource_type="backup",
            resource_id="backup-1",
            metadata_json={"error": "object missing"},
        )
        skipped = AuditLog(
            actor="viewer",
            role="viewer",
            action="repository.view",
            resource_type="repository",
            resource_id="repo-2",
            metadata_json={},
        )
        db.add_all([manual, config, failure, skipped])
        db.flush()

        page = list_audit_review(db=db, _=None)
        manual_page = list_audit_review(reason="privileged_non_admin", role="operator", db=db, _=None)

        by_id = {item["id"]: item for item in page.items}
        assert set(by_id) == {str(manual.id), str(config.id), str(failure.id)}
        assert by_id[str(manual.id)]["reason"] == "privileged_non_admin"
        assert by_id[str(config.id)]["reason"] == "configuration_change"
        assert by_id[str(failure.id)]["reason"] == "failure_event"
        assert [item["id"] for item in manual_page.items] == [str(manual.id)]


def test_rbac_review_reports_default_token_role_and_non_admin_privileged_actions() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        db.add_all(
            [
                AuditLog(
                    actor="operator",
                    role="operator",
                    action="repository.create",
                    resource_type="repository",
                    resource_id="repo-1",
                    metadata_json={},
                ),
                AuditLog(
                    actor="viewer",
                    role="viewer",
                    action="repository.view",
                    resource_type="repository",
                    resource_id="repo-2",
                    metadata_json={},
                ),
            ]
        )
        db.flush()
        settings = Settings(api_token="change-me", api_default_role="admin")

        rows = rbac_review(db=db, settings=settings, _=None)
        summary = dashboard_summary(db=db, settings=settings, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["default_api_token"].status == "fail"
        assert by_check["default_role_admin"].status == "warn"
        assert by_check["non_admin_privileged_actions"].count == 1
        assert by_check["audit_role_coverage"].count == 2
        assert summary.rbac_review_items == 3


def test_restore_readiness_reports_storage_artifacts_and_restore_exercise() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        with_artifact = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={"artifacts": {"source_sbom": {"storage_key": "source.json"}}},
        )
        missing_artifact = Scan(application_id=app.id, status=ScanStatus.succeeded)
        restore_log = AuditLog(
            actor="admin",
            role="admin",
            action="restore.verify",
            resource_type="backup",
            resource_id="restore-1",
            metadata_json={},
            created_at=now_utc(),
        )
        db.add_all([with_artifact, missing_artifact, restore_log])
        db.flush()
        db.add_all(
            [
                Sbom(
                    application_id=app.id,
                    scan_id=with_artifact.id,
                    sbom_digest="restore-active",
                    storage_key="restore-active.json",
                    active=True,
                    sbom_kind="source",
                ),
                Sbom(
                    application_id=app.id,
                    scan_id=missing_artifact.id,
                    sbom_digest="restore-missing-key",
                    storage_key="",
                    active=True,
                    sbom_kind="source",
                ),
            ]
        )
        db.flush()
        settings = Settings(minio_endpoint="", minio_access_key="", minio_secret_key="", minio_bucket="")

        rows = restore_readiness(db=db, settings=settings, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["object_storage"].status == "fail"
        assert by_check["sbom_storage_keys"].status == "fail"
        assert by_check["sbom_storage_keys"].count == 1
        assert by_check["source_sbom_artifacts"].status == "warn"
        assert by_check["restore_exercise_30d"].status == "ok"
        assert by_check["restore_exercise_30d"].count == 1


def test_list_risk_acceptance_review_reports_accepted_risk_and_vex_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        accepted = create_finding(db, app, severity=Severity.high, status=FindingStatus.accepted_risk)
        vex_finding = create_finding(db, app, severity=Severity.medium)
        db.add(
            VexStatement(
                finding_id=vex_finding.id,
                status=VexStatus.not_affected,
                justification="not reachable",
                approved_by="security",
                review_date=now_utc() - timedelta(days=1),
            )
        )
        db.flush()

        page = list_risk_acceptance_review(db=db, _=None)
        expired_page = list_risk_acceptance_review(expired=True, source="vex", db=db, _=None)
        severity_page = list_risk_acceptance_review(severity=Severity.high, source="finding", db=db, _=None)

        sources = {(item["source"], item["finding_id"]) for item in page.items}
        assert sources == {("finding", str(accepted.id)), ("vex", str(vex_finding.id))}
        assert [item["finding_id"] for item in expired_page.items] == [str(vex_finding.id)]
        assert expired_page.items[0]["expired"] is True
        assert expired_page.items[0]["application_name"] == app.name
        assert [item["finding_id"] for item in severity_page.items] == [str(accepted.id)]


def test_list_rollout_gaps_reports_deployment_blockers_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        empty_repo = create_repository(db, "empty-rollout")
        repo = create_repository(db, "rollout")
        app = create_application(db, repo, "rollout-app")
        stale_scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=31),
        )
        db.add(stale_scan)
        finding = create_finding(db, app, severity=Severity.critical)
        db.flush()

        page = list_rollout_gaps(db=db, _=None)
        owner_page = list_rollout_gaps(issue_type="missing_owner", db=db, _=None)
        summary = dashboard_summary(
            db=db,
            settings=Settings(api_token="custom-token", api_default_role="operator"),
            _=None,
        )

        issues = {(item["issue_type"], item["repository_name"], item["application_name"]) for item in page.items}
        assert ("missing_application", empty_repo.name, None) in issues
        assert ("missing_owner", repo.name, app.name) in issues
        assert ("missing_active_source_sbom", repo.name, app.name) in issues
        assert ("stale_scan", repo.name, app.name) in issues
        assert ("open_critical_high", repo.name, app.name) in issues
        assert owner_page.items[0]["application_name"] == app.name
        assert summary.rollout_gap_items == 5
        assert finding.status == FindingStatus.open


def test_rollout_baseline_reports_inventory_visibility_and_classification() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        visible = create_repository(db, "visible")
        visible.visibility = "private"
        missing_visibility = create_repository(db, "missing-visibility")
        missing_visibility.visibility = None
        missing_visibility.archived = True
        fork = create_repository(db, "fork")
        fork.visibility = "public"
        fork.fork = True
        db.flush()

        rows = rollout_baseline(db=db, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["repository_inventory"].count == 3
        assert by_check["repository_inventory"].target == 54
        assert by_check["visibility_known"].count == 1
        assert by_check["visibility_known"].status == "warn"
        assert by_check["classification_known"].count == 0
        assert by_check["archived_repositories"].count == 1
        assert by_check["fork_repositories"].count == 1


def test_list_application_readiness_reports_active_application_gaps() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "readiness")
        app = create_application(db, repo, "readiness-app")
        app.criticality = "unknown-tier"
        archived = create_application(db, repo, "archived-app")
        archived.lifecycle = Lifecycle.archived
        db.flush()

        page = list_application_readiness(db=db, _=None)
        owner_page = list_application_readiness(issue_type="missing_owner", db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        issues = {item["issue_type"] for item in page.items}
        assert issues == {"missing_owner", "unknown_criticality", "missing_active_source_sbom", "stale_scan"}
        assert all(item["application_name"] == app.name for item in page.items)
        assert [item["application_name"] for item in owner_page.items] == [app.name]
        assert archived.name not in {item["application_name"] for item in page.items}
        assert summary.application_readiness_items == 4


def test_scan_targets_reports_success_rate_failures_partials_and_stale_apps() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "scan-targets")
        covered = create_application(db, repo, "covered")
        stale = create_application(db, repo, "stale")
        db.add_all(
            [
                Scan(application_id=covered.id, status=ScanStatus.succeeded, created_at=now_utc()),
                Scan(application_id=covered.id, status=ScanStatus.failed, created_at=now_utc()),
                Scan(application_id=covered.id, status=ScanStatus.partially_succeeded, created_at=now_utc()),
                Scan(
                    application_id=stale.id,
                    status=ScanStatus.succeeded,
                    created_at=now_utc() - timedelta(days=31),
                ),
            ]
        )
        db.flush()

        rows = scan_targets(db=db, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["daily_scan_success_rate"].actual_percent == 50.0
        assert by_check["daily_scan_success_rate"].status == "warn"
        assert by_check["failed_scans"].count == 1
        assert by_check["partial_scans"].count == 1
        assert by_check["stale_active_applications"].count == 1


def test_github_integration_health_reports_configuration_and_failure_classes() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.high)
        failed_sync = Job(
            job_type=JobType.repository_sync,
            status=JobStatus.failed,
            last_error="GitHub API rate limit exceeded",
        )
        issue_action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="failed",
            provider="github",
            metadata_json={"error": "github request timeout"},
        )
        db.add_all([failed_sync, issue_action])
        db.flush()
        settings = Settings(github_token=None, github_app_id=None, github_private_key=None, github_webhook_secret=None)

        rows = github_integration_health(db=db, settings=settings, _=None)
        summary = dashboard_summary(db=db, settings=settings, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["github_auth"].status == "fail"
        assert by_check["github_webhook_secret"].status == "warn"
        assert by_check["repository_sync_failures"].count == 1
        assert by_check["github_issue_failures"].count == 1
        assert by_check["github_rate_limit"].count == 1
        assert by_check["github_timeout"].count == 1
        assert summary.github_integration_issues == 6


def test_list_webhook_intake_reports_event_repository_status_and_duplicates() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        body = '{"repository": {"full_name": "local/demo"}}'
        first = Job(
            job_type=JobType.repository_sync,
            status=JobStatus.queued,
            payload={"event": "push", "body": body},
            created_at=now_utc(),
        )
        duplicate = Job(
            job_type=JobType.repository_sync,
            status=JobStatus.failed,
            payload={"event": "push", "body": body},
            last_error="duplicate webhook",
            created_at=now_utc() + timedelta(minutes=5),
        )
        skipped = Job(job_type=JobType.scan, status=JobStatus.queued, payload={"event": "push"})
        db.add_all([first, duplicate, skipped])
        db.flush()

        page = list_webhook_intake(event="push", duplicate_candidate=True, db=db, _=None)
        failed_page = list_webhook_intake(status=JobStatus.failed, db=db, _=None)

        assert {item["job_id"] for item in page.items} == {str(first.id), str(duplicate.id)}
        assert page.items[0]["repository"] == "local/demo"
        assert all(item["duplicate_candidate"] is True for item in page.items)
        assert [item["job_id"] for item in failed_page.items] == [str(duplicate.id)]


def test_list_scanner_failures_reports_summary_errors_and_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        partial = Scan(
            application_id=app.id,
            status=ScanStatus.partially_succeeded,
            tool="trivy",
            result_summary={"scanner_failures": [{"tool": "trivy", "error": "trivy db update failed"}]},
        )
        failed = Scan(
            application_id=app.id,
            status=ScanStatus.failed,
            tool="syft",
            error_message="syft timeout",
        )
        healthy = Scan(application_id=app.id, status=ScanStatus.succeeded, tool="osv")
        db.add_all([partial, failed, healthy])
        db.flush()

        page = list_scanner_failures(db=db, _=None)
        trivy_page = list_scanner_failures(tool="trivy", status=ScanStatus.partially_succeeded, db=db, _=None)

        by_tool = {item["tool"]: item for item in page.items}
        assert set(by_tool) == {"syft", "trivy"}
        assert by_tool["trivy"]["failure_type"] == "trivy_db_update"
        assert by_tool["syft"]["failure_type"] == "timeout"
        assert [item["scan_id"] for item in trivy_page.items] == [str(partial.id)]
        assert trivy_page.items[0]["application_name"] == app.name


def test_list_dependency_updates_reports_renovate_dependabot_and_ci_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        renovate_finding = create_finding(db, app, severity=Severity.high)
        dependabot_finding = create_finding(db, app, severity=Severity.medium)
        renovate = RemediationAction(
            finding_id=renovate_finding.id,
            action_type="ai_fix",
            status="created",
            provider="renovate",
            branch="renovate/pkg-1",
            metadata_json={"pull_request_url": "https://github.com/local/demo/pull/1", "ci_passed": False},
        )
        dependabot = RemediationAction(
            finding_id=dependabot_finding.id,
            action_type="github_issue",
            status="created",
            provider="dependabot",
            branch="dependabot/npm/pkg-2",
            metadata_json={"ci_passed": True, "update_kind": "minor"},
        )
        db.add_all([renovate, dependabot])
        db.flush()

        page = list_dependency_updates(db=db, _=None)
        failed_page = list_dependency_updates(provider="renovate", ci_failed=True, db=db, _=None)

        by_source = {item["update_source"]: item for item in page.items}
        assert set(by_source) == {"dependabot", "renovate"}
        assert by_source["renovate"]["ci_passed"] is False
        assert by_source["dependabot"]["ci_passed"] is True
        assert [item["action_id"] for item in failed_page.items] == [str(renovate.id)]


def test_list_remediation_coverage_reports_missing_actions_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "coverage")
        app = create_application(db, repo)
        covered = create_finding(db, app, severity=Severity.critical, risk_score=9.5)
        missing = create_finding(db, app, severity=Severity.high, risk_score=8.0)
        db.add(
            RemediationAction(
                finding_id=covered.id,
                action_type="github_issue",
                status="created",
                provider="github",
                url="https://github.com/local/demo/issues/1",
            )
        )
        db.flush()

        page = list_remediation_coverage(db=db, _=None)
        missing_page = list_remediation_coverage(missing_action=True, severity=Severity.high, db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_finding = {item["finding_id"]: item for item in page.items}
        assert by_finding[str(covered.id)]["has_issue_or_pr"] is True
        assert by_finding[str(missing.id)]["has_issue_or_pr"] is False
        assert by_finding[str(covered.id)]["coverage_percent"] == 50.0
        assert [item["finding_id"] for item in missing_page.items] == [str(missing.id)]
        assert summary.remediation_coverage_items == 1


def test_list_resolution_verification_reports_rescan_validation_and_close_gaps() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "resolution-verification")
        missing_app = create_application(db, repo, "missing-rescan-app")
        failed_app = create_application(db, repo, "failed-validation-app")
        close_app = create_application(db, repo, "missing-close-app")
        missing_rescan = create_finding(db, missing_app, severity=Severity.critical)
        failed_validation = create_finding(db, failed_app, severity=Severity.high)
        missing_close = create_finding(db, close_app, severity=Severity.medium, status=FindingStatus.resolved)
        missing_close.resolved_at = now_utc()
        missing_rescan_action = RemediationAction(
            finding_id=missing_rescan.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            created_at=now_utc() - timedelta(days=2),
        )
        failed_scan = Scan(application_id=failed_app.id, status=ScanStatus.failed, created_at=now_utc())
        close_scan = Scan(application_id=close_app.id, status=ScanStatus.succeeded, created_at=now_utc())
        db.add_all([missing_rescan_action, failed_scan, close_scan])
        db.flush()
        failed_validation_action = RemediationAction(
            finding_id=failed_validation.id,
            action_type="ai_fix",
            status="failed",
            provider="watchtower",
            metadata_json={"validation_status": "failed", "validation_scan_id": str(failed_scan.id)},
        )
        missing_close_action = RemediationAction(
            finding_id=missing_close.id,
            action_type="github_issue",
            status="created",
            provider="github",
            created_at=now_utc() - timedelta(days=1),
            metadata_json={"validation_status": "succeeded", "validation_scan_id": str(close_scan.id)},
        )
        db.add_all([failed_validation_action, missing_close_action])
        db.flush()

        page = list_resolution_verification(db=db, _=None)
        close_page = list_resolution_verification(issue_type="missing_issue_close", db=db, _=None)

        issues = {(item["issue_type"], item["finding_id"]) for item in page.items}
        assert ("missing_rescan", str(missing_rescan.id)) in issues
        assert ("failed_validation", str(failed_validation.id)) in issues
        assert ("missing_issue_close", str(missing_close.id)) in issues
        assert [item["finding_id"] for item in close_page.items] == [str(missing_close.id)]
        assert close_page.items[0]["close_state"] == "pending_close"


def test_list_failure_signals_reports_classified_operations_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)
        db.add_all(
            [
                Job(
                    job_type=JobType.repository_sync,
                    status=JobStatus.failed,
                    last_error="GitHub API rate limit exceeded",
                ),
                Scan(
                    application_id=app.id,
                    status=ScanStatus.failed,
                    tool="syft",
                    error_message="syft scanner failed",
                ),
                RemediationAction(
                    finding_id=finding.id,
                    action_type="github_issue",
                    status="skipped_duplicate",
                    provider="github",
                    metadata_json={"skipped_reason": "github issue already created"},
                ),
                Notification(
                    channel="slack",
                    severity=Severity.critical,
                    subject="failed delivery",
                    body="webhook timeout",
                    status="failed",
                ),
            ]
        )
        db.flush()

        page = list_failure_signals(db=db, _=None)
        duplicate_page = list_failure_signals(signal_type="duplicate_suppression", db=db, _=None)
        summary = dashboard_summary(
            db=db,
            settings=Settings(github_token="token", github_webhook_secret="secret", api_token="custom"),
            _=None,
        )

        signal_types = {item["signal_type"] for item in page.items}
        assert {"duplicate_suppression", "github_rate_limit", "scanner_failure", "worker_failure"} <= signal_types
        assert [item["source"] for item in duplicate_page.items] == ["remediation_action"]
        assert duplicate_page.items[0]["application_name"] == app.name
        assert summary.failure_signal_items == 4


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


def test_list_isolated_safeguards_reports_missing_controls_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "restricted-safeguards")
        repo.source_classification = SourceClassification.restricted
        app = create_application(db, repo, "restricted-app")
        db.flush()

        page = list_isolated_safeguards(db=db, _=None)
        filtered = list_isolated_safeguards(issue_type="missing_owner", db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        issue_types = {item["issue_type"] for item in page.items}
        assert issue_types == {
            "github_provider_mixed",
            "missing_owner",
            "missing_scan",
            "missing_active_source_sbom",
            "missing_artifact_storage",
        }
        assert all(item["application_id"] == str(app.id) for item in page.items)
        assert filtered.items[0]["issue_type"] == "missing_owner"
        assert summary.isolated_safeguard_items == 5


def test_list_secrets_review_reports_scan_and_metadata_without_secret_values() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        scan = Scan(
            application_id=app.id,
            status=ScanStatus.succeeded,
            result_summary={
                "secrets": [
                    {
                        "severity": "critical",
                        "title": "Hardcoded API key",
                        "path": ".env",
                        "secret": "SUPER_SECRET_VALUE",
                    }
                ]
            },
        )
        audit_log = AuditLog(
            actor="operator",
            role="admin",
            action="settings.update",
            resource_type="settings",
            resource_id="github",
            metadata_json={"token": "AUDIT_SECRET_VALUE"},
        )
        job = Job(
            job_type=JobType.scan,
            status=JobStatus.failed,
            last_error="credential token detected in worker output",
        )
        db.add_all([scan, audit_log, job])
        db.flush()

        page = list_secrets_review(db=db, _=None)
        filtered = list_secrets_review(source="scan", severity="critical", db=db, _=None)

        assert {item["source"] for item in page.items} == {"scan", "audit", "job"}
        assert [item["source"] for item in filtered.items] == ["scan"]
        assert filtered.items[0]["detail"] == ".env"
        rendered = " ".join(str(item.get("detail")) for item in page.items)
        assert "SUPER_SECRET_VALUE" not in rendered
        assert "AUDIT_SECRET_VALUE" not in rendered


def test_worker_posture_reports_timeout_isolated_and_credential_issues() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "restricted-worker")
        repo.source_classification = SourceClassification.restricted
        app = create_application(db, repo)
        db.add_all(
            [
                Job(
                    job_type=JobType.scan,
                    status=JobStatus.running,
                    started_at=now_utc() - timedelta(minutes=10),
                ),
                Job(
                    job_type=JobType.scan,
                    status=JobStatus.timed_out,
                    last_error="worker timed out",
                ),
                Job(
                    job_type=JobType.repository_sync,
                    status=JobStatus.failed,
                    last_error="GitHub 401 credential failure",
                ),
                Scan(
                    application_id=app.id,
                    status=ScanStatus.failed,
                    error_message="scanner failed",
                ),
            ]
        )
        db.flush()

        rows = worker_posture(
            db=db,
            settings=Settings(worker_job_timeout_seconds=60),
            _=None,
        )

        by_check = {row.check: row for row in rows}
        assert by_check["job_timeout"].status == "ok"
        assert by_check["stale_running_jobs"].count == 1
        assert by_check["timed_out_jobs"].count == 1
        assert by_check["isolated_scan_failures"].count == 1
        assert by_check["credential_failure_signals"].count == 1


def test_list_exploit_intel_reports_kev_epss_and_filters() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        kev_finding = create_finding(db, app, severity=Severity.high, risk_score=8.0)
        critical_finding = create_finding(db, app, severity=Severity.critical, risk_score=9.9)
        kev_vulnerability = db.get(Vulnerability, kev_finding.vulnerability_id)
        critical_vulnerability = db.get(Vulnerability, critical_finding.vulnerability_id)
        assert kev_vulnerability is not None
        assert critical_vulnerability is not None
        kev_vulnerability.title = "CISA KEV known exploited package"
        kev_vulnerability.references = ["https://example.test/kev"]
        critical_vulnerability.cvss_score = 9.8
        db.flush()

        page = list_exploit_intel(db=db, _=None)
        kev_page = list_exploit_intel(kev=True, db=db, _=None)
        critical_page = list_exploit_intel(severity=Severity.critical, db=db, _=None)

        by_id = {item["finding_id"]: item for item in page.items}
        assert set(by_id) == {str(kev_finding.id), str(critical_finding.id)}
        assert by_id[str(kev_finding.id)]["kev"] is True
        assert by_id[str(critical_finding.id)]["epss_signal"] is True
        assert [item["finding_id"] for item in kev_page.items] == [str(kev_finding.id)]
        assert [item["finding_id"] for item in critical_page.items] == [str(critical_finding.id)]


def test_quarterly_review_reports_governance_counts_and_dashboard_count() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db, "quarterly")
        repo.source_classification = SourceClassification.restricted
        app = create_application(db, repo)
        app.lifecycle = Lifecycle.deprecated
        app.criticality = "unclassified"
        app.production = True
        app.auto_merge_enabled = True
        db.flush()

        rows = quarterly_review(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_item = {row.item: row for row in rows}
        assert by_item["deprecation_candidates"].count == 1
        assert by_item["owner_tier_review"].count == 1
        assert by_item["external_exposure_review"].count == 1
        assert by_item["github_app_permissions_review"].count == 1
        assert by_item["isolated_classification_review"].count == 1
        assert by_item["auto_merge_scope_review"].count == 1
        assert all(row.status == "warn" for row in rows)
        assert summary.quarterly_review_items == 6


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


def test_list_audit_logs_filters_and_returns_metadata() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        matching = AuditLog(
            actor="api-token",
            role="operator",
            action="repository.create",
            resource_type="repository",
            resource_id="repo-1",
            metadata_json={"source": "test"},
        )
        skipped = AuditLog(
            actor="api-token",
            role="viewer",
            action="job.create",
            resource_type="job",
            resource_id="job-1",
            metadata_json={},
        )
        db.add_all([matching, skipped])
        db.flush()

        page = list_audit_logs(
            role="operator",
            action="repository.create",
            resource_type="repository",
            db=db,
            _=None,
        )

        assert [item["id"] for item in page.items] == [str(matching.id)]
        assert page.items[0]["metadata_json"] == {"source": "test"}


def test_operations_readiness_reports_configuration_without_secret_values() -> None:
    settings = Settings(
        github_token="secret-token",
        github_app_id="123",
        github_private_key="private-key",
        github_webhook_secret="webhook-secret",
        slack_webhook_url="https://hooks.slack.test/demo",
        minio_secret_key="minio-secret",
        api_default_role="operator",
    )

    rows = operations_readiness(settings=settings, _=None)

    by_check = {row.check: row for row in rows}
    assert by_check["github_token"].configured is True
    assert by_check["github_app"].configured is True
    assert by_check["notifications"].configured is True
    rendered = " ".join(row.detail for row in rows)
    assert "secret-token" not in rendered
    assert "private-key" not in rendered
    assert "webhook-secret" not in rendered
    assert "minio-secret" not in rendered


def test_daily_operations_reports_failures_and_24h_jobs() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        app = create_application(db, repo)
        finding = create_finding(db, app, severity=Severity.critical)
        finding.created_at = now_utc() - timedelta(days=8)
        db.add_all(
            [
                Job(job_type=JobType.repository_sync, status=JobStatus.succeeded),
                Job(job_type=JobType.scan, status=JobStatus.succeeded),
                Job(job_type=JobType.notification, status=JobStatus.failed, last_error="webhook failed"),
                Notification(
                    channel="slack",
                    severity=Severity.critical,
                    subject="subject",
                    body="body",
                    status="failed",
                ),
                VexStatement(
                    finding_id=finding.id,
                    status=VexStatus.not_affected,
                    justification="temporary",
                    approved_by="security",
                    review_date=now_utc() - timedelta(days=1),
                ),
            ]
        )
        db.flush()

        rows = daily_operations(db=db, _=None)

        by_check = {row.check: row for row in rows}
        assert by_check["repository_sync_24h"].status == "ok"
        assert by_check["scan_jobs_24h"].status == "ok"
        assert by_check["unhealthy_jobs"].status == "fail"
        assert by_check["failed_notifications"].status == "fail"
        assert by_check["expired_vex"].status == "warn"
        assert by_check["sla_breaches"].status == "fail"


def test_kpi_summary_reports_core_operational_metrics() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        repo = create_repository(db)
        covered = create_application(db, repo, "covered")
        missing = create_application(db, repo, "missing")
        covered.auto_merge_enabled = True
        success_scan = Scan(application_id=covered.id, status=ScanStatus.succeeded)
        failed_scan = Scan(application_id=missing.id, status=ScanStatus.failed)
        db.add_all([success_scan, failed_scan])
        db.flush()
        db.add(
            Sbom(
                application_id=covered.id,
                scan_id=success_scan.id,
                sbom_digest="digest",
                storage_key="sbom.json",
                active=True,
                sbom_kind="source",
            )
        )
        open_finding = create_finding(db, covered, severity=Severity.critical)
        open_finding.created_at = now_utc() - timedelta(days=8)
        create_finding(db, missing, severity=Severity.high, status=FindingStatus.resolved)
        action = RemediationAction(
            finding_id=open_finding.id,
            action_type="ai_fix",
            status="created",
            provider="watchtower",
            metadata_json={
                "validation_status": "succeeded",
                "update_kind": "patch",
                "ci_passed": True,
                "tier_allows": True,
                "touches_forbidden_path": False,
            },
        )
        sent = Notification(channel="slack", severity=Severity.high, subject="sent", body="body", status="sent")
        failed = Notification(
            channel="slack",
            severity=Severity.high,
            subject="failed",
            body="body",
            status="failed",
        )
        db.add_all([action, sent, failed])
        db.flush()

        rows = kpi_summary(db=db, _=None)
        summary = dashboard_summary(db=db, _=None)

        by_metric = {row.metric: row for row in rows}
        assert by_metric["sbom_coverage_percent"].value == 50.0
        assert by_metric["scan_failure_rate_percent"].value == 50.0
        assert by_metric["open_finding_count"].value == 1
        assert by_metric["resolved_finding_count"].value == 1
        assert by_metric["notification_success_rate_percent"].value == 50.0
        assert by_metric["ai_fix_success_rate_percent"].value == 100.0
        assert by_metric["auto_merge_eligible_count"].value == 1
        assert by_metric["sla_breach_count"].value == 1
        assert summary.scan_failure_rate_percent == 50.0
        assert summary.notification_failure_count == 1


def test_repository_rollout_filters_and_reports_coverage() -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        github_repo = create_repository(db, "github")
        local_repo = create_repository(db, "local")
        local_repo.provider = RepositoryProvider.local
        app_owned = create_application(db, github_repo, "owned")
        app_owned.owner = "team"
        app_missing_owner = create_application(db, github_repo, "missing-owner")
        create_application(db, local_repo, "local-app")
        scan = Scan(application_id=app_owned.id, status=ScanStatus.succeeded, created_at=now_utc())
        stale_scan = Scan(
            application_id=app_missing_owner.id,
            status=ScanStatus.succeeded,
            created_at=now_utc() - timedelta(days=31),
        )
        db.add_all([scan, stale_scan])
        db.flush()
        db.add(
            Sbom(
                application_id=app_owned.id,
                scan_id=scan.id,
                sbom_digest="rollout-digest",
                storage_key="rollout.json",
                active=True,
                sbom_kind="source",
            )
        )
        create_finding(db, app_owned, severity=Severity.high)
        db.flush()

        page = list_repository_rollout(provider=RepositoryProvider.github, archived=False, db=db, _=None)

        assert [item["repository_name"] for item in page.items] == [github_repo.name]
        item = page.items[0]
        assert item["application_count"] == 2
        assert item["owner_completeness_percent"] == 50.0
        assert item["active_sbom_coverage_percent"] == 50.0
        assert item["latest_scan_status"] == "succeeded"
        assert item["stale_scan_count"] == 1
        assert item["open_critical_high_count"] == 1


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
