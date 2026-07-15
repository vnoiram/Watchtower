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
    Vulnerability,
    now_utc,
)
from api.app.routers.applications import list_applications
from api.app.routers.components import list_component_applications, list_components
from api.app.routers.findings import list_findings
from api.app.routers.findings import enqueue_github_issue as enqueue_github_issue_endpoint
from api.app.routers.remediation_actions import list_remediation_actions
from api.app.routers.sboms import list_sboms
from api.app.routers.technologies import list_technologies
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
        path=".",
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
