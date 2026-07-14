from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.models import (
    Application,
    ApplicationType,
    Component,
    Finding,
    FindingStatus,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    Severity,
    SourceClassification,
    TriggerType,
    Vulnerability,
)
from api.app.services.scanner import NormalizedFinding
from api.app.services.vulnerabilities import upsert_findings


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_repo_app_scan(db: Session, tmp_path: Path) -> tuple[Repository, Application, Scan]:
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
        internet_exposed=True,
        production=True,
    )
    db.add(app)
    db.flush()
    scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
    db.add(scan)
    db.flush()
    return repo, app, scan


def normalized(
    vulnerability_id: str = "GHSA-123",
    purl: str = "pkg:pypi/demo@1.0.0",
    severity: Severity = Severity.high,
) -> NormalizedFinding:
    return NormalizedFinding(
        source="osv",
        vulnerability_id=vulnerability_id,
        package_name="demo",
        package_version="1.0.0",
        ecosystem="PyPI",
        purl=purl,
        severity=severity,
        fixed_version="1.0.1",
        title="demo issue",
        references=("https://example.test",),
    )


def test_upsert_findings_creates_component_vulnerability_and_finding(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app, scan = create_repo_app_scan(db, tmp_path)

        result = upsert_findings(db, app, scan, [normalized()], resolved_sources={"osv"})
        db.flush()

        assert result.finding_count == 1
        assert result.resolved_count == 0
        assert db.scalar(select(Component).where(Component.purl == "pkg:pypi/demo@1.0.0"))
        assert db.scalar(select(Vulnerability).where(Vulnerability.external_id == "GHSA-123"))
        finding = db.scalar(select(Finding))
        assert result.notification_finding_ids == [finding.id]
        assert result.resolved_finding_ids == []
        assert finding.status == FindingStatus.open
        assert finding.first_seen_scan_id == scan.id
        assert finding.last_seen_scan_id == scan.id
        assert finding.risk_score == 10.0


def test_upsert_findings_updates_existing_without_duplicate(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app, first_scan = create_repo_app_scan(db, tmp_path)
        upsert_findings(db, app, first_scan, [normalized(severity=Severity.medium)], resolved_sources={"osv"})
        second_scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
        db.add(second_scan)
        db.flush()

        result = upsert_findings(
            db,
            app,
            second_scan,
            [normalized(severity=Severity.critical)],
            resolved_sources={"osv"},
        )
        db.flush()

        findings = list(db.scalars(select(Finding)))
        assert result.finding_count == 1
        assert result.notification_finding_ids == []
        assert len(findings) == 1
        assert findings[0].first_seen_scan_id == first_scan.id
        assert findings[0].last_seen_scan_id == second_scan.id
        assert findings[0].severity == Severity.critical


def test_upsert_findings_resolves_missing_open_finding(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app, first_scan = create_repo_app_scan(db, tmp_path)
        upsert_findings(db, app, first_scan, [normalized()], resolved_sources={"osv"})
        second_scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
        db.add(second_scan)
        db.flush()

        result = upsert_findings(db, app, second_scan, [], resolved_sources={"osv"})
        db.flush()

        finding = db.scalar(select(Finding))
        assert result.resolved_count == 1
        assert result.resolved_finding_ids == [finding.id]
        assert finding.status == FindingStatus.resolved
        assert finding.resolved_at is not None


def test_upsert_findings_does_not_resolve_when_no_sources_succeeded(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app, first_scan = create_repo_app_scan(db, tmp_path)
        upsert_findings(db, app, first_scan, [normalized()], resolved_sources={"osv"})
        second_scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
        db.add(second_scan)
        db.flush()

        result = upsert_findings(db, app, second_scan, [], resolved_sources=set())
        db.flush()

        finding = db.scalar(select(Finding))
        assert result.resolved_count == 0
        assert result.resolved_finding_ids == []
        assert finding.status == FindingStatus.open


def test_upsert_findings_reports_reopened_finding_for_notification(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        _, app, first_scan = create_repo_app_scan(db, tmp_path)
        upsert_findings(db, app, first_scan, [normalized()], resolved_sources={"osv"})
        second_scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
        db.add(second_scan)
        db.flush()
        upsert_findings(db, app, second_scan, [], resolved_sources={"osv"})
        third_scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.running)
        db.add(third_scan)
        db.flush()

        result = upsert_findings(db, app, third_scan, [normalized()], resolved_sources={"osv"})
        db.flush()

        finding = db.scalar(select(Finding))
        assert finding.status == FindingStatus.open
        assert result.notification_finding_ids == [finding.id]
        assert result.resolved_finding_ids == []
