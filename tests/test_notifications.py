from pathlib import Path

import pytest
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
    Notification,
    Repository,
    RepositoryProvider,
    Scan,
    ScanStatus,
    Severity,
    SourceClassification,
    TriggerType,
    Vulnerability,
)
from api.app.services.notifications import (
    deliver_notification,
    enqueue_finding_notifications,
    webhook_payload,
)


def session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_finding(
    db: Session,
    tmp_path: Path,
    *,
    severity: Severity = Severity.high,
    status: FindingStatus = FindingStatus.open,
) -> tuple[Finding, Scan]:
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
    component = Component(
        purl="pkg:pypi/demo@1.0.0",
        ecosystem="PyPI",
        name="demo",
        version="1.0.0",
    )
    vulnerability = Vulnerability(
        source="osv",
        external_id="GHSA-123",
        severity=severity,
        references=[],
    )
    db.add_all([app, component, vulnerability])
    db.flush()
    scan = Scan(application_id=app.id, trigger_type=TriggerType.manual, status=ScanStatus.succeeded)
    db.add(scan)
    db.flush()
    finding = Finding(
        application_id=app.id,
        component_id=component.id,
        vulnerability_id=vulnerability.id,
        status=status,
        severity=severity,
        first_seen_scan_id=scan.id,
        last_seen_scan_id=scan.id,
        fixed_version="1.0.1",
        risk_score=8.0,
    )
    db.add(finding)
    db.flush()
    return finding, scan


def settings(
    *,
    slack: str | None = None,
    discord: str | None = None,
) -> Settings:
    return Settings(slack_webhook_url=slack, discord_webhook_url=discord)


def test_enqueue_finding_notifications_creates_slack_notification(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path, severity=Severity.critical)

        notifications = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(slack="https://hooks.slack.test/demo"),
        )

        assert len(notifications) == 1
        notification = notifications[0]
        assert notification.channel == "slack"
        assert notification.severity == Severity.critical
        assert notification.status == "queued"
        assert notification.metadata_json["finding_id"] == str(finding.id)
        assert notification.metadata_json["scan_id"] == str(scan.id)


def test_enqueue_finding_notifications_creates_discord_notification(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)

        notifications = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(discord="https://discord.test/webhook"),
        )

        assert len(notifications) == 1
        assert notifications[0].channel == "discord"
        assert webhook_payload(notifications[0])["content"].startswith("High vulnerability detected")


def test_enqueue_finding_notifications_creates_both_channels(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)

        notifications = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(
                slack="https://hooks.slack.test/demo",
                discord="https://discord.test/webhook",
            ),
        )

        assert {notification.channel for notification in notifications} == {"slack", "discord"}


def test_enqueue_finding_notifications_skips_unconfigured_and_low_risk(
    tmp_path: Path,
) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path, severity=Severity.medium)

        assert (
            enqueue_finding_notifications(
                db,
                finding_ids=[finding.id],
                scan_id=scan.id,
                settings=settings(slack="https://hooks.slack.test/demo"),
            )
            == []
        )
        finding.severity = Severity.high
        assert enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(),
        ) == []


def test_enqueue_finding_notifications_skips_non_open_status(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path, status=FindingStatus.resolved)

        notifications = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(slack="https://hooks.slack.test/demo"),
        )

        assert notifications == []


def test_enqueue_finding_notifications_suppresses_duplicates(tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)
        configured = settings(slack="https://hooks.slack.test/demo")

        first = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=configured,
        )
        second = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=configured,
        )

        assert len(first) == 1
        assert second == []
        assert len(list(db.scalars(select(Notification)))) == 1


def test_deliver_notification_posts_slack_payload(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)
        notification = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(slack="https://hooks.slack.test/demo"),
        )[0]
        calls = []

        def fake_post(url: str, *, json: dict, timeout: float):
            calls.append((url, json, timeout))
            return type("Response", (), {"status_code": 200, "text": "ok"})()

        monkeypatch.setattr("api.app.services.notifications.httpx.post", fake_post)

        deliver_notification(
            notification,
            settings=settings(slack="https://hooks.slack.test/demo"),
        )

        assert notification.status == "sent"
        assert notification.sent_at is not None
        assert calls[0][0] == "https://hooks.slack.test/demo"
        assert "text" in calls[0][1]


def test_deliver_notification_posts_discord_payload(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)
        notification = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(discord="https://discord.test/webhook"),
        )[0]
        calls = []

        def fake_post(url: str, *, json: dict, timeout: float):
            calls.append((url, json, timeout))
            return type("Response", (), {"status_code": 204, "text": ""})()

        monkeypatch.setattr("api.app.services.notifications.httpx.post", fake_post)

        deliver_notification(
            notification,
            settings=settings(discord="https://discord.test/webhook"),
        )

        assert notification.status == "sent"
        assert calls[0][0] == "https://discord.test/webhook"
        assert "content" in calls[0][1]


def test_deliver_notification_preserves_queued_on_failure(monkeypatch, tmp_path: Path) -> None:
    SessionLocal = session_factory()
    with SessionLocal() as db:
        finding, scan = create_finding(db, tmp_path)
        notification = enqueue_finding_notifications(
            db,
            finding_ids=[finding.id],
            scan_id=scan.id,
            settings=settings(slack="https://hooks.slack.test/demo"),
        )[0]

        def fake_post(url: str, *, json: dict, timeout: float):
            return type("Response", (), {"status_code": 500, "text": "bad"})()

        monkeypatch.setattr("api.app.services.notifications.httpx.post", fake_post)

        with pytest.raises(RuntimeError, match="webhook failed"):
            deliver_notification(
                notification,
                settings=settings(slack="https://hooks.slack.test/demo"),
            )

        assert notification.status == "queued"
        assert notification.sent_at is None
