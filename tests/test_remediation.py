from pathlib import Path
from uuid import uuid4

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
    Severity,
    SourceClassification,
    Vulnerability,
)
from api.app.services.remediation import (
    enqueue_github_issue_requests,
    mark_issue_actions_pending_provider,
)


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_finding(
    db: Session,
    tmp_path: Path,
    *,
    provider: RepositoryProvider = RepositoryProvider.github,
    severity: Severity = Severity.high,
    status: FindingStatus = FindingStatus.open,
    fixed_version: str | None = "1.0.1",
) -> Finding:
    repo_uid = str(uuid4())
    repo = Repository(
        provider=provider,
        provider_repository_id=repo_uid,
        owner="local",
        name=f"demo-{repo_uid}",
        url=f"https://github.com/local/demo-{repo_uid}"
        if provider == RepositoryProvider.github
        else None,
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
    component = Component(
        purl=f"pkg:pypi/demo-{repo_uid}@1.0.0",
        ecosystem="PyPI",
        name=f"demo-{repo_uid}",
        version="1.0.0",
    )
    vulnerability = Vulnerability(
        source="osv",
        external_id=f"GHSA-{repo_uid}",
        severity=severity,
        references=[],
    )
    db.add_all([app, component, vulnerability])
    db.flush()
    finding = Finding(
        application_id=app.id,
        component_id=component.id,
        vulnerability_id=vulnerability.id,
        status=status,
        severity=severity,
        fixed_version=fixed_version,
        risk_score=8.0,
    )
    db.add(finding)
    db.flush()
    return finding


def test_enqueue_github_issue_requests_creates_remediation_action(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path, severity=Severity.critical)

        actions = enqueue_github_issue_requests(db, finding_ids=[finding.id])

        assert len(actions) == 1
        action = actions[0]
        assert action.action_type == "github_issue"
        assert action.provider == "github"
        assert action.status == "queued"
        assert action.fixed_version == "1.0.1"
        assert action.metadata_json["finding_id"] == str(finding.id)
        assert action.metadata_json["severity"] == "critical"


def test_enqueue_github_issue_requests_skips_ineligible_findings(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        medium = create_finding(db, tmp_path, severity=Severity.medium)
        resolved = create_finding(db, tmp_path, status=FindingStatus.resolved)
        no_fix = create_finding(db, tmp_path, fixed_version=None)
        local = create_finding(db, tmp_path, provider=RepositoryProvider.local)

        actions = enqueue_github_issue_requests(
            db,
            finding_ids=[medium.id, resolved.id, no_fix.id, local.id],
        )

        assert actions == []
        assert list(db.scalars(select(RemediationAction))) == []


def test_enqueue_github_issue_requests_suppresses_duplicates(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)

        first = enqueue_github_issue_requests(db, finding_ids=[finding.id])
        second = enqueue_github_issue_requests(db, finding_ids=[finding.id])

        assert len(first) == 1
        assert second == []
        assert len(list(db.scalars(select(RemediationAction)))) == 1


def test_mark_issue_actions_pending_provider(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]

        updated = mark_issue_actions_pending_provider(db, action_ids=[action.id])

        assert updated == [action]
        assert action.status == "pending_provider"
        assert action.metadata_json["dry_run"] is True
        assert action.metadata_json["reason"] == "github issue delivery is not implemented yet"
