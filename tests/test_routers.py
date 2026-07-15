from datetime import timedelta
from uuid import UUID

from sqlalchemy import create_engine
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
    now_utc,
)
from api.app.routers.applications import list_applications
from api.app.routers.findings import list_findings


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
