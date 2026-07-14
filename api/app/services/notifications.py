from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import (
    Application,
    Component,
    Finding,
    FindingStatus,
    Notification,
    Severity,
    Vulnerability,
    now_utc,
)

IMMEDIATE_SEVERITIES = {Severity.critical, Severity.high}
TERMINAL_NOTIFICATION_STATUSES = {"queued", "sent"}
NOTIFICATION_KIND = "vulnerability_alert"


@dataclass(frozen=True)
class NotificationDeliveryTarget:
    channel: str
    webhook_url: str


def notification_targets(settings: Settings) -> list[NotificationDeliveryTarget]:
    targets: list[NotificationDeliveryTarget] = []
    if settings.slack_webhook_url:
        targets.append(NotificationDeliveryTarget(channel="slack", webhook_url=settings.slack_webhook_url))
    if settings.discord_webhook_url:
        targets.append(
            NotificationDeliveryTarget(channel="discord", webhook_url=settings.discord_webhook_url)
        )
    return targets


def enqueue_finding_notifications(
    db: Session,
    *,
    finding_ids: list[UUID],
    scan_id: UUID,
    settings: Settings,
) -> list[Notification]:
    targets = notification_targets(settings)
    if not targets or not finding_ids:
        return []

    created: list[Notification] = []
    for finding_id in finding_ids:
        finding = db.get(Finding, finding_id)
        if not should_notify_finding(finding):
            continue
        application = db.get(Application, finding.application_id)
        component = db.get(Component, finding.component_id)
        vulnerability = db.get(Vulnerability, finding.vulnerability_id)
        if not application or not component or not vulnerability:
            continue
        for target in targets:
            if notification_exists(db, finding_id=finding.id, channel=target.channel):
                continue
            notification = Notification(
                channel=target.channel,
                severity=finding.severity,
                subject=notification_subject(finding.severity, vulnerability.external_id),
                body=notification_body(application, component, vulnerability, finding),
                status="queued",
                metadata_json={
                    "notification_kind": NOTIFICATION_KIND,
                    "finding_id": str(finding.id),
                    "application_id": str(finding.application_id),
                    "component_id": str(finding.component_id),
                    "vulnerability_id": str(finding.vulnerability_id),
                    "scan_id": str(scan_id),
                },
            )
            db.add(notification)
            db.flush()
            created.append(notification)
    return created


def should_notify_finding(finding: Finding | None) -> bool:
    return bool(
        finding
        and finding.status == FindingStatus.open
        and finding.severity in IMMEDIATE_SEVERITIES
    )


def notification_exists(db: Session, *, finding_id: UUID, channel: str) -> bool:
    notifications = db.scalars(
        select(Notification).where(
            Notification.channel == channel,
            Notification.status.in_(TERMINAL_NOTIFICATION_STATUSES),
        )
    )
    finding_id_value = str(finding_id)
    return any(
        notification.metadata_json.get("notification_kind") == NOTIFICATION_KIND
        and notification.metadata_json.get("finding_id") == finding_id_value
        for notification in notifications
    )


def notification_subject(severity: Severity, external_id: str) -> str:
    label = "Critical" if severity == Severity.critical else "High"
    return f"{label} vulnerability detected: {external_id}"


def notification_body(
    application: Application,
    component: Component,
    vulnerability: Vulnerability,
    finding: Finding,
) -> str:
    fixed_version = finding.fixed_version or "not available"
    return (
        f"{finding.severity.value.upper()} vulnerability {vulnerability.external_id} "
        f"detected in {application.name}: {component.purl}. "
        f"Source: {vulnerability.source}. Fixed version: {fixed_version}. "
        f"Risk score: {finding.risk_score:.1f}."
    )


def deliver_notification(
    notification: Notification,
    *,
    settings: Settings,
    timeout_seconds: float = 10.0,
) -> None:
    webhook_url = webhook_url_for_channel(notification.channel, settings)
    if not webhook_url:
        raise RuntimeError(f"webhook URL is not configured for channel: {notification.channel}")

    payload = webhook_payload(notification)
    response = httpx.post(webhook_url, json=payload, timeout=timeout_seconds)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(
            f"{notification.channel} webhook failed with status {response.status_code}: {response.text}"
        )

    notification.status = "sent"
    notification.sent_at = now_utc()


def webhook_url_for_channel(channel: str, settings: Settings) -> str | None:
    if channel == "slack":
        return settings.slack_webhook_url
    if channel == "discord":
        return settings.discord_webhook_url
    return None


def webhook_payload(notification: Notification) -> dict[str, str]:
    text = f"{notification.subject}\n{notification.body}"
    if notification.channel == "discord":
        return {"content": text}
    return {"text": text}
