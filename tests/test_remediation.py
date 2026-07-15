from pathlib import Path
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from api.app.database import Base
from api.app.config import Settings
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
from api.app.services.github import GitHubAuthError
from api.app.services.remediation import (
    enqueue_ai_fix_requests,
    build_github_issue_payload,
    enqueue_github_issue_requests,
    process_github_issue_closures,
    process_github_issue_actions,
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


def test_enqueue_ai_fix_requests_creates_remediation_action(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path, severity=Severity.high)

        actions = enqueue_ai_fix_requests(db, finding_ids=[finding.id])

        assert len(actions) == 1
        action = actions[0]
        assert action.action_type == "ai_fix"
        assert action.provider == "watchtower"
        assert action.status == "queued"
        assert action.fixed_version == "1.0.1"
        assert action.metadata_json == {
            "finding_id": str(finding.id),
            "application_id": str(finding.application_id),
            "severity": "high",
            "fixed_version": "1.0.1",
            "component_id": str(finding.component_id),
            "vulnerability_id": str(finding.vulnerability_id),
        }


def test_enqueue_ai_fix_requests_skips_ineligible_and_duplicate_findings(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        resolved = create_finding(db, tmp_path, status=FindingStatus.resolved)
        no_fix = create_finding(db, tmp_path, fixed_version=None)
        duplicate = create_finding(db, tmp_path)
        existing = RemediationAction(
            finding_id=duplicate.id,
            action_type="ai_fix",
            status="queued",
            provider="watchtower",
            fixed_version=duplicate.fixed_version,
            metadata_json={"finding_id": str(duplicate.id)},
        )
        db.add(existing)
        db.flush()

        actions = enqueue_ai_fix_requests(
            db,
            finding_ids=[resolved.id, no_fix.id, duplicate.id],
        )

        assert actions == []
        assert list(db.scalars(select(RemediationAction))) == [existing]


def test_enqueue_ai_fix_requests_raises_for_missing_finding_id(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        missing_id = uuid4()
        create_finding(db, tmp_path)

        try:
            enqueue_ai_fix_requests(db, finding_ids=[missing_id])
        except RuntimeError as exc:
            assert str(exc) == f"finding not found: {missing_id}"
        else:
            raise AssertionError("expected RuntimeError")


def test_enqueue_ai_fix_requests_filters_by_application_id(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        target = create_finding(db, tmp_path)
        other = create_finding(db, tmp_path)

        actions = enqueue_ai_fix_requests(db, application_id=target.application_id)

        assert len(actions) == 1
        assert actions[0].finding_id == target.id
        assert actions[0].metadata_json["application_id"] == str(target.application_id)
        action_findings = [action.finding_id for action in db.scalars(select(RemediationAction))]
        assert action_findings == [target.id]
        assert other.id not in action_findings


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text

    def json(self) -> dict:
        return self._payload


def test_build_github_issue_payload_uses_finding_context(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]

        payload = build_github_issue_payload(db, action)

        assert not isinstance(payload, str)
        assert payload["title"].startswith("[Watchtower] high vulnerability GHSA-")
        assert "demo-" in payload["title"]
        assert "- Application: demo" in payload["body"]
        assert f"- Vulnerability: {action.metadata_json['vulnerability_external_id']}" in payload["body"]
        assert "- Fixed version: 1.0.1" in payload["body"]
        assert "- Risk score: 8.0" in payload["body"]
        assert f"- Finding ID: {finding.id}" in payload["body"]
        assert f"- Remediation action ID: {action.id}" in payload["body"]


def test_process_github_issue_actions_creates_issue(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]
        calls = []

        def fake_post(url: str, **kwargs) -> FakeResponse:
            calls.append((url, kwargs))
            return FakeResponse(
                201,
                {
                    "number": 42,
                    "html_url": "https://github.com/local/demo/issues/42",
                    "url": "https://api.github.com/repos/local/demo/issues/42",
                },
            )

        monkeypatch.setattr("api.app.services.remediation.httpx.post", fake_post)

        processed = process_github_issue_actions(
            db,
            action_ids=[action.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "created"
        assert action.provider_id == "42"
        assert action.url == "https://github.com/local/demo/issues/42"
        assert action.metadata_json["github_issue_url"] == "https://github.com/local/demo/issues/42"
        assert action.metadata_json["html_url"] == "https://github.com/local/demo/issues/42"
        assert action.metadata_json["api_url"] == "https://api.github.com/repos/local/demo/issues/42"
        assert calls[0][0].startswith("https://api.github.com/repos/local/demo-")
        assert calls[0][1]["headers"]["Authorization"] == "Bearer token"
        assert calls[0][1]["json"]["title"].startswith("[Watchtower] high vulnerability")


def test_process_github_issue_actions_prefers_app_token(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]
        repository = db.get(Repository, finding.application.repository_id)
        tokens = []
        posts = []

        def fake_get_token(repository, settings: Settings) -> str:
            tokens.append((repository.owner, repository.name, settings.github_app_id))
            return "app-token"

        def fake_post(url: str, **kwargs) -> FakeResponse:
            posts.append((url, kwargs))
            return FakeResponse(
                201,
                {
                    "number": 42,
                    "html_url": "https://github.com/local/demo/issues/42",
                    "url": "https://api.github.com/repos/local/demo/issues/42",
                },
            )

        monkeypatch.setattr(
            "api.app.services.remediation.get_repository_installation_token",
            fake_get_token,
        )
        monkeypatch.setattr("api.app.services.remediation.httpx.post", fake_post)

        processed = process_github_issue_actions(
            db,
            action_ids=[action.id],
            settings=Settings(
                github_app_id="12345",
                github_private_key="pem",
                github_token="pat-token",
            ),
        )

        assert processed == [action]
        assert action.status == "created"
        assert tokens == [(repository.owner, repository.name, "12345")]
        assert posts[0][1]["headers"]["Authorization"] == "Bearer app-token"


def test_process_github_issue_actions_fails_when_app_token_fails(
    monkeypatch,
    tmp_path: Path,
) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]
        calls = []

        def fake_get_token(*args, **kwargs) -> str:
            raise GitHubAuthError("github installation lookup failed with status 404: not found")

        def fake_post(*args, **kwargs) -> FakeResponse:
            calls.append((args, kwargs))
            return FakeResponse(201, {"number": 42})

        monkeypatch.setattr(
            "api.app.services.remediation.get_repository_installation_token",
            fake_get_token,
        )
        monkeypatch.setattr("api.app.services.remediation.httpx.post", fake_post)

        processed = process_github_issue_actions(
            db,
            action_ids=[action.id],
            settings=Settings(
                github_app_id="12345",
                github_private_key="pem",
                github_token="pat-token",
            ),
        )

        assert processed == [action]
        assert action.status == "failed"
        assert action.metadata_json["error"] == (
            "github installation lookup failed with status 404: not found"
        )
        assert calls == []


def test_process_github_issue_actions_fails_without_auth(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]

        processed = process_github_issue_actions(db, action_ids=[action.id], settings=Settings())

        assert processed == [action]
        assert action.status == "failed"
        assert action.metadata_json["error"] == "github authentication is not configured"


def test_process_github_issue_actions_records_http_failure(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]

        def fake_post(*args, **kwargs) -> FakeResponse:
            return FakeResponse(422, text="bad request")

        monkeypatch.setattr("api.app.services.remediation.httpx.post", fake_post)

        processed = process_github_issue_actions(
            db,
            action_ids=[action.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "failed"
        assert action.metadata_json["error"] == "github issue create failed with status 422: bad request"


def test_process_github_issue_actions_records_exception(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        action = enqueue_github_issue_requests(db, finding_ids=[finding.id])[0]

        def fake_post(*args, **kwargs) -> FakeResponse:
            raise RuntimeError("network down")

        monkeypatch.setattr("api.app.services.remediation.httpx.post", fake_post)

        processed = process_github_issue_actions(
            db,
            action_ids=[action.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "failed"
        assert action.metadata_json["error"] == "github issue create failed: network down"


def test_process_github_issue_actions_skips_duplicate_created_action(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path)
        created = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            url="https://github.com/local/demo/issues/42",
            metadata_json={"repository_id": str(finding.application.repository_id)},
        )
        queued = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="queued",
            provider="github",
            metadata_json={"repository_id": str(finding.application.repository_id)},
        )
        db.add_all([created, queued])
        db.flush()

        processed = process_github_issue_actions(
            db,
            action_ids=[queued.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [queued]
        assert queued.status == "skipped_duplicate"
        assert queued.metadata_json["skipped_reason"] == "github issue already created"


def test_process_github_issue_closures_closes_created_issue(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path, status=FindingStatus.resolved)
        repository = db.get(Repository, finding.application.repository_id)
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            url=f"https://github.com/{repository.owner}/{repository.name}/issues/42",
            metadata_json={
                "repository_id": str(repository.id),
                "close_error": "previous failure",
            },
        )
        db.add(action)
        db.flush()
        calls = []

        def fake_patch(url: str, **kwargs) -> FakeResponse:
            calls.append((url, kwargs))
            return FakeResponse(200, {"state": "closed"})

        monkeypatch.setattr("api.app.services.remediation.httpx.patch", fake_patch)

        processed = process_github_issue_closures(
            db,
            finding_ids=[finding.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "closed"
        assert "github_issue_closed_at" in action.metadata_json
        assert action.metadata_json["close_api_url"].endswith(f"/issues/{action.provider_id}")
        assert "close_error" not in action.metadata_json
        assert calls == [
            (
                f"https://api.github.com/repos/{repository.owner}/{repository.name}/issues/42",
                {
                    "json": {"state": "closed", "state_reason": "completed"},
                    "headers": {
                        "Accept": "application/vnd.github+json",
                        "Authorization": "Bearer token",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    "timeout": 10.0,
                },
            )
        ]


def test_process_github_issue_closures_records_http_failure(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path, status=FindingStatus.resolved)
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="42",
            metadata_json={"repository_id": str(finding.application.repository_id)},
        )
        db.add(action)
        db.flush()

        def fake_patch(*args, **kwargs) -> FakeResponse:
            return FakeResponse(404, text="not found")

        monkeypatch.setattr("api.app.services.remediation.httpx.patch", fake_patch)

        processed = process_github_issue_closures(
            db,
            finding_ids=[finding.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "close_failed"
        assert action.metadata_json["close_error"] == (
            "github issue close failed with status 404: not found"
        )


def test_process_github_issue_closures_records_exception(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding = create_finding(db, tmp_path, status=FindingStatus.resolved)
        action = RemediationAction(
            finding_id=finding.id,
            action_type="github_issue",
            status="close_failed",
            provider="github",
            provider_id="42",
            metadata_json={"repository_id": str(finding.application.repository_id)},
        )
        db.add(action)
        db.flush()

        def fake_patch(*args, **kwargs) -> FakeResponse:
            raise RuntimeError("network down")

        monkeypatch.setattr("api.app.services.remediation.httpx.patch", fake_patch)

        processed = process_github_issue_closures(
            db,
            finding_ids=[finding.id],
            settings=Settings(github_token="token"),
        )

        assert processed == [action]
        assert action.status == "close_failed"
        assert action.metadata_json["close_error"] == "github issue close failed: network down"


def test_process_github_issue_closures_skips_ineligible_actions(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        open_finding = create_finding(db, tmp_path)
        resolved_finding = create_finding(db, tmp_path, status=FindingStatus.resolved)
        no_provider_id = RemediationAction(
            finding_id=resolved_finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            metadata_json={"repository_id": str(resolved_finding.application.repository_id)},
        )
        open_action = RemediationAction(
            finding_id=open_finding.id,
            action_type="github_issue",
            status="created",
            provider="github",
            provider_id="43",
            metadata_json={"repository_id": str(open_finding.application.repository_id)},
        )
        closed_action = RemediationAction(
            finding_id=resolved_finding.id,
            action_type="github_issue",
            status="closed",
            provider="github",
            provider_id="44",
            metadata_json={"repository_id": str(resolved_finding.application.repository_id)},
        )
        db.add_all([no_provider_id, open_action, closed_action])
        db.flush()
        calls = []

        def fake_patch(*args, **kwargs) -> FakeResponse:
            calls.append((args, kwargs))
            return FakeResponse(200)

        monkeypatch.setattr("api.app.services.remediation.httpx.patch", fake_patch)

        processed = process_github_issue_closures(
            db,
            finding_ids=[],
            settings=Settings(github_token="token"),
        )

        assert processed == []
        assert calls == []
