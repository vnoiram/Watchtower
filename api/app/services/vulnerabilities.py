from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import (
    Application,
    Component,
    Finding,
    FindingStatus,
    Scan,
    Vulnerability,
    now_utc,
)
from api.app.services.scanner import NormalizedFinding, calculate_risk_score
from api.app.services.sbom import split_purl_namespace


@dataclass(frozen=True)
class FindingPersistenceResult:
    finding_count: int
    resolved_count: int
    notification_finding_ids: list[UUID]
    resolved_finding_ids: list[UUID]


def upsert_component(db: Session, finding: NormalizedFinding) -> Component:
    component = db.scalar(select(Component).where(Component.purl == finding.purl))
    if component:
        component.ecosystem = component.ecosystem or finding.ecosystem
        component.name = component.name or finding.package_name
        component.version = component.version or finding.package_version
        component.namespace = component.namespace or split_purl_namespace(finding.purl)
        return component

    component = Component(
        purl=finding.purl,
        ecosystem=finding.ecosystem,
        namespace=split_purl_namespace(finding.purl),
        name=finding.package_name,
        version=finding.package_version,
    )
    db.add(component)
    db.flush()
    return component


def upsert_vulnerability(db: Session, finding: NormalizedFinding) -> Vulnerability:
    vulnerability = db.scalar(
        select(Vulnerability).where(
            Vulnerability.source == finding.source,
            Vulnerability.external_id == finding.vulnerability_id,
        )
    )
    if vulnerability:
        vulnerability.title = finding.title or vulnerability.title
        vulnerability.severity = finding.severity
        vulnerability.references = list(finding.references)
        return vulnerability

    vulnerability = Vulnerability(
        source=finding.source,
        external_id=finding.vulnerability_id,
        title=finding.title,
        severity=finding.severity,
        references=list(finding.references),
    )
    db.add(vulnerability)
    db.flush()
    return vulnerability


def upsert_findings(
    db: Session,
    application: Application,
    scan: Scan,
    findings: list[NormalizedFinding],
    *,
    resolved_sources: set[str] | None = None,
) -> FindingPersistenceResult:
    seen_keys: set[tuple[str, str, str]] = set()
    seen_finding_ids: set[object] = set()
    notification_finding_ids: list[UUID] = []

    for normalized in findings:
        key = (normalized.source, normalized.vulnerability_id, normalized.purl)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        component = upsert_component(db, normalized)
        vulnerability = upsert_vulnerability(db, normalized)
        risk_score = calculate_risk_score(
            normalized.severity,
            internet_exposed=application.internet_exposed,
            production=application.production,
        )
        finding = db.scalar(
            select(Finding).where(
                Finding.application_id == application.id,
                Finding.component_id == component.id,
                Finding.vulnerability_id == vulnerability.id,
            )
        )
        if finding:
            was_resolved = finding.status == FindingStatus.resolved
            finding.status = FindingStatus.open
            finding.last_seen_scan_id = scan.id
            finding.severity = normalized.severity
            finding.fixed_version = normalized.fixed_version
            finding.risk_score = risk_score
            finding.resolved_at = None
            if was_resolved:
                notification_finding_ids.append(finding.id)
        else:
            finding = Finding(
                application_id=application.id,
                component_id=component.id,
                vulnerability_id=vulnerability.id,
                status=FindingStatus.open,
                severity=normalized.severity,
                first_seen_scan_id=scan.id,
                last_seen_scan_id=scan.id,
                fixed_version=normalized.fixed_version,
                risk_score=risk_score,
            )
            db.add(finding)
            db.flush()
            notification_finding_ids.append(finding.id)
        seen_finding_ids.add(finding.id)

    resolved_finding_ids = resolve_missing_findings(
        db,
        application,
        seen_finding_ids=seen_finding_ids,
        resolved_sources=resolved_sources,
    )
    return FindingPersistenceResult(
        finding_count=len(seen_keys),
        resolved_count=len(resolved_finding_ids),
        notification_finding_ids=notification_finding_ids,
        resolved_finding_ids=resolved_finding_ids,
    )


def resolve_missing_findings(
    db: Session,
    application: Application,
    *,
    seen_finding_ids: set[object],
    resolved_sources: set[str] | None,
) -> list[UUID]:
    if resolved_sources is not None and not resolved_sources:
        return []

    stmt = (
        select(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(
            Finding.application_id == application.id,
            Finding.status == FindingStatus.open,
        )
    )
    if seen_finding_ids:
        stmt = stmt.where(Finding.id.not_in(seen_finding_ids))
    if resolved_sources is not None:
        stmt = stmt.where(Vulnerability.source.in_(resolved_sources))

    resolved_at = now_utc()
    resolved_finding_ids: list[UUID] = []
    for finding in db.scalars(stmt):
        finding.status = FindingStatus.resolved
        finding.resolved_at = resolved_at
        resolved_finding_ids.append(finding.id)
    return resolved_finding_ids
