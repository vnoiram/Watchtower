from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app import models, schemas
from api.app.config import Settings, get_settings
from api.app.database import get_db
from api.app.deps import Principal, get_principal

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/data-protection", response_model=list[schemas.DataProtectionOut])
def data_protection(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    storage_configured = bool(
        settings.minio_endpoint
        and settings.minio_access_key
        and settings.minio_secret_key
        and settings.minio_bucket
    )
    github_secret_configured = bool(settings.github_webhook_secret and (settings.github_token or settings.github_app_id))
    missing_storage_keys = sum(1 for sbom in db.scalars(select(models.Sbom)) if not sbom.storage_key)
    classification_missing = sum(1 for sbom in db.scalars(select(models.Sbom)) if not sbom.sbom_kind)
    artifact_count = _stored_artifact_count(db)
    return [
        _protection("object_storage", storage_configured, 1 if storage_configured else 0, "Object storage settings are configured"),
        _protection("github_secrets", github_secret_configured, 1 if github_secret_configured else 0, "GitHub token/app and webhook secret are configured"),
        _protection("sbom_storage_keys", missing_storage_keys == 0, missing_storage_keys, "SBOM records without storage keys"),
        _protection("sbom_classification", classification_missing == 0, classification_missing, "SBOM records without kind classification"),
        _protection("stored_artifacts", artifact_count > 0, artifact_count, "Scan artifacts with storage keys"),
    ]


@router.get("/findings", response_model=schemas.CursorPage)
def list_security_findings(
    limit: int = 50,
    finding_type: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = []
    stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    for scan, application, repository in db.execute(stmt):
        for current_type, finding in _security_findings(scan.result_summary):
            if finding_type and current_type != finding_type:
                continue
            current_severity = _finding_severity(finding)
            if severity and current_severity != severity:
                continue
            items.append(
                schemas.SecurityFindingOut(
                    finding_type=current_type,
                    severity=current_severity,
                    title=_finding_title(finding),
                    detail=_finding_detail(finding),
                    scan_id=scan.id,
                    scan_status=scan.status,
                    scan_created_at=scan.created_at,
                    application_id=application.id,
                    application_name=application.name,
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                ).model_dump(mode="json")
            )
            if len(items) >= min(limit, 100):
                return schemas.CursorPage(items=items, next_cursor=None)
    return schemas.CursorPage(items=items, next_cursor=None)


@router.get("/secrets-review", response_model=schemas.CursorPage)
def list_secrets_review(
    limit: int = 50,
    source: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = secrets_review_items(db)
    if source:
        items = [item for item in items if item["source"] == source]
    if severity:
        items = [item for item in items if item["severity"] == severity]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/secret-scan-coverage", response_model=schemas.CursorPage)
def list_secret_scan_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = secret_scan_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["max_severity"] == severity]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/sast-coverage", response_model=schemas.CursorPage)
def list_sast_coverage(
    limit: int = 50,
    gap_type: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = sast_coverage_items(db)
    if gap_type:
        items = [item for item in items if item["gap_type"] == gap_type]
    if severity:
        items = [item for item in items if item["max_severity"] == severity]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/exploit-intel", response_model=schemas.CursorPage)
def list_exploit_intel(
    limit: int = 50,
    kev: bool | None = None,
    severity: models.Severity | None = None,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_principal),
):
    items = exploit_intel_items(db)
    if kev is not None:
        items = [item for item in items if item["kev"] is kev]
    if severity:
        items = [item for item in items if item["severity"] == severity.value]
    return schemas.CursorPage(items=items[: min(limit, 100)], next_cursor=None)


@router.get("/rbac-review", response_model=list[schemas.RbacReviewOut])
def rbac_review(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
    _: Principal = Depends(get_principal),
):
    return rbac_review_items(db, settings)


def rbac_review_count(db: Session, settings: Settings) -> int:
    return sum(1 for item in rbac_review_items(db, settings) if item.status != "ok")


def secret_scan_coverage_count(db: Session) -> int:
    return len(secret_scan_coverage_items(db))


def sast_coverage_count(db: Session) -> int:
    return len(sast_coverage_items(db))


def secret_scan_coverage_items(db: Session) -> list[dict]:
    return _security_scan_coverage_items(
        db,
        finding_type="secret",
        evidence_tokens={"secret", "secrets", "gitleaks", "trufflehog", "detect-secrets"},
        missing_gap="missing_secret_scan",
        finding_gap="secret_findings_present",
        failure_gap="scanner_failure",
    )


def sast_coverage_items(db: Session) -> list[dict]:
    return _security_scan_coverage_items(
        db,
        finding_type="sast",
        evidence_tokens={"sast", "semgrep", "bandit", "gosec", "codeql", "static"},
        missing_gap="missing_sast_scan",
        finding_gap="sast_findings_present",
        failure_gap="scanner_failure",
    )


def secrets_review_items(db: Session) -> list[dict]:
    items = []
    scan_stmt = (
        select(models.Scan, models.Application, models.Repository)
        .join(models.Application, models.Scan.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .order_by(models.Scan.created_at.desc(), models.Scan.id.asc())
    )
    for scan, application, repository in db.execute(scan_stmt):
        for finding_type, finding in _security_findings(scan.result_summary):
            if finding_type != "secret" and not _secretish(finding):
                continue
            items.append(
                schemas.SecretReviewOut(
                    source="scan",
                    source_id=str(scan.id),
                    severity=_finding_severity(finding),
                    title=_finding_title(finding),
                    detail=_safe_secret_detail(finding),
                    application_id=application.id,
                    application_name=application.name,
                    repository_id=repository.id,
                    repository_owner=repository.owner,
                    repository_name=repository.name,
                    created_at=scan.created_at,
                ).model_dump(mode="json")
            )
    for item in _secret_error_items(db):
        items.append(item)
    return items


def _security_scan_coverage_items(
    db: Session,
    *,
    finding_type: str,
    evidence_tokens: set[str],
    missing_gap: str,
    finding_gap: str,
    failure_gap: str,
) -> list[dict]:
    rows = list(
        db.execute(
            select(models.Application, models.Repository)
            .join(models.Repository, models.Application.repository_id == models.Repository.id)
            .order_by(models.Application.name.asc(), models.Application.id.asc())
        )
    )
    latest_scans = _latest_scan_by_application(db)
    items = []
    for application, repository in rows:
        scan = latest_scans.get(application.id)
        findings = _findings_of_type(scan.result_summary if scan else None, finding_type)
        has_evidence = _has_scan_evidence(scan, evidence_tokens, finding_type)
        failures = _scanner_failures_for(scan, evidence_tokens)
        max_severity = _max_finding_severity(findings)
        if not has_evidence:
            items.append(
                _security_scan_coverage_item(
                    missing_gap,
                    application,
                    repository,
                    scan,
                    has_evidence,
                    len(findings),
                    max_severity,
                    f"Latest scan has no {finding_type} evidence",
                )
            )
        if findings:
            items.append(
                _security_scan_coverage_item(
                    finding_gap,
                    application,
                    repository,
                    scan,
                    has_evidence,
                    len(findings),
                    max_severity,
                    f"Latest scan reported {len(findings)} {finding_type} finding(s)",
                )
            )
        if failures:
            items.append(
                _security_scan_coverage_item(
                    failure_gap,
                    application,
                    repository,
                    scan,
                    has_evidence,
                    len(findings),
                    max_severity,
                    "; ".join(failures),
                )
            )
    return items


def exploit_intel_items(db: Session) -> list[dict]:
    stmt = (
        select(models.Finding, models.Application, models.Repository, models.Component, models.Vulnerability)
        .join(models.Application, models.Finding.application_id == models.Application.id)
        .join(models.Repository, models.Application.repository_id == models.Repository.id)
        .join(models.Component, models.Finding.component_id == models.Component.id)
        .join(models.Vulnerability, models.Finding.vulnerability_id == models.Vulnerability.id)
        .order_by(models.Finding.risk_score.desc(), models.Finding.created_at.asc())
    )
    items = []
    for finding, application, repository, component, vulnerability in db.execute(stmt):
        kev = _kev_signal(vulnerability)
        epss = _epss_signal(vulnerability, finding)
        if not kev and not epss:
            continue
        items.append(
            schemas.ExploitIntelOut(
                finding_id=finding.id,
                severity=finding.severity,
                risk_score=finding.risk_score,
                application_id=application.id,
                application_name=application.name,
                repository_id=repository.id,
                repository_owner=repository.owner,
                repository_name=repository.name,
                component_name=component.name,
                vulnerability_external_id=vulnerability.external_id,
                cvss_score=vulnerability.cvss_score,
                kev=kev,
                epss_signal=epss,
                detail=_exploit_detail(vulnerability, kev, epss),
            ).model_dump(mode="json")
        )
    return items


def rbac_review_items(db: Session, settings: Settings) -> list[schemas.RbacReviewOut]:
    logs = list(db.scalars(select(models.AuditLog)))
    default_token = settings.api_token == "change-me"
    default_role_admin = settings.api_default_role == "admin"
    non_admin_privileged = [
        log for log in logs if log.role != "admin" and _privileged_action(log.action)
    ]
    roles = {log.role for log in logs}
    return [
        _rbac_check(
            "default_api_token",
            "fail" if default_token else "ok",
            1 if default_token else 0,
            "API token is using the default value" if default_token else "API token is customized",
        ),
        _rbac_check(
            "default_role_admin",
            "warn" if default_role_admin else "ok",
            1 if default_role_admin else 0,
            f"default_role={settings.api_default_role}",
        ),
        _rbac_check(
            "non_admin_privileged_actions",
            "warn" if non_admin_privileged else "ok",
            len(non_admin_privileged),
            "Privileged audit events performed by a non-admin role",
        ),
        _rbac_check(
            "audit_role_coverage",
            "ok" if roles else "warn",
            len(roles),
            "Roles observed in audit logs: " + (", ".join(sorted(roles)) if roles else "none"),
        ),
    ]


def _protection(check: str, configured: bool, count: int, detail: str) -> schemas.DataProtectionOut:
    return schemas.DataProtectionOut(
        check=check,
        status="ok" if configured else "warn",
        configured=configured,
        count=count,
        detail=detail,
    )


def _rbac_check(check: str, status: str, count: int, detail: str) -> schemas.RbacReviewOut:
    return schemas.RbacReviewOut(check=check, status=status, count=count, detail=detail)


def _privileged_action(action: str) -> bool:
    return action in {
        "application.create",
        "job.create",
        "repository.create",
        "repository.scan.enqueue",
        "scan.create",
        "vex.create",
    }


def _stored_artifact_count(db: Session) -> int:
    count = 0
    for scan in db.scalars(select(models.Scan)):
        artifacts = (scan.result_summary or {}).get("artifacts") or {}
        if not isinstance(artifacts, dict):
            continue
        count += sum(1 for artifact in artifacts.values() if isinstance(artifact, dict) and artifact.get("storage_key"))
    return count


def _security_findings(result_summary: dict[str, Any] | None) -> list[tuple[str, dict]]:
    if not result_summary:
        return []
    items = []
    for key, finding_type in [
        ("secrets", "secret"),
        ("sast", "sast"),
        ("license_findings", "license"),
        ("security_findings", "security"),
    ]:
        raw = result_summary.get(key) or []
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            continue
        for finding in raw:
            if isinstance(finding, dict):
                items.append((finding_type, finding))
    return items


def _secret_error_items(db: Session) -> list[dict]:
    items = []
    for audit_log in db.scalars(select(models.AuditLog)):
        metadata = audit_log.metadata_json or {}
        text = f"{audit_log.action} {metadata}".lower()
        if not _secret_text(text):
            continue
        items.append(
            schemas.SecretReviewOut(
                source="audit",
                source_id=str(audit_log.id),
                title=audit_log.action,
                detail="Audit metadata references secret-like material",
                created_at=audit_log.created_at,
            ).model_dump(mode="json")
        )
    for job in db.scalars(select(models.Job).where(models.Job.last_error.is_not(None))):
        if not _secret_text(job.last_error or ""):
            continue
        items.append(
            schemas.SecretReviewOut(
                source="job",
                source_id=str(job.id),
                title=job.job_type.value,
                detail="Job error references secret-like material",
                created_at=job.created_at,
            ).model_dump(mode="json")
        )
    return items


def _secretish(finding: dict) -> bool:
    return _secret_text(" ".join(str(value) for value in finding.values()))


def _secret_text(value: str) -> bool:
    text = value.lower()
    return any(token in text for token in ["secret", "credential", "token", "api key", "apikey", "private key"])


def _safe_secret_detail(finding: dict) -> str | None:
    value = finding.get("path") or finding.get("file") or finding.get("rule_id") or finding.get("type")
    return str(value) if value else None


def _kev_signal(vulnerability: models.Vulnerability) -> bool:
    text = _vulnerability_text(vulnerability)
    return "cisa" in text or "kev" in text or "known exploited" in text


def _epss_signal(vulnerability: models.Vulnerability, finding: models.Finding) -> bool:
    text = _vulnerability_text(vulnerability)
    return "epss" in text or (vulnerability.cvss_score or 0) >= 9.0 or finding.severity == models.Severity.critical


def _vulnerability_text(vulnerability: models.Vulnerability) -> str:
    return " ".join(
        [
            vulnerability.external_id or "",
            vulnerability.title or "",
            vulnerability.description or "",
            " ".join(vulnerability.references or []),
        ]
    ).lower()


def _exploit_detail(vulnerability: models.Vulnerability, kev: bool, epss: bool) -> str:
    signals = []
    if kev:
        signals.append("KEV-like metadata")
    if epss:
        signals.append("EPSS/high exploitability signal")
    return ", ".join(signals) or vulnerability.external_id


def _finding_severity(finding: dict) -> str | None:
    value = finding.get("severity") or finding.get("level")
    return str(value) if value else None


def _finding_title(finding: dict) -> str:
    return str(finding.get("title") or finding.get("rule_id") or finding.get("type") or "security finding")


def _finding_detail(finding: dict) -> str | None:
    value = finding.get("detail") or finding.get("message") or finding.get("description") or finding.get("path")
    return str(value) if value else None


def _latest_scan_by_application(db: Session) -> dict:
    latest = {}
    scans = db.scalars(select(models.Scan).order_by(models.Scan.created_at.desc(), models.Scan.id.desc()))
    for scan in scans:
        latest.setdefault(scan.application_id, scan)
    return latest


def _findings_of_type(result_summary: dict[str, Any] | None, finding_type: str) -> list[dict]:
    return [finding for current_type, finding in _security_findings(result_summary) if current_type == finding_type]


def _has_scan_evidence(scan: models.Scan | None, evidence_tokens: set[str], finding_type: str) -> bool:
    if not scan:
        return False
    summary = scan.result_summary or {}
    if finding_type in summary:
        return True
    artifacts = summary.get("artifacts") or {}
    if isinstance(artifacts, dict) and any(_matches_tokens(str(key), evidence_tokens) for key in artifacts):
        return True
    text = " ".join(str(value) for value in [scan.scan_type, scan.tool, summary.get("scanner"), summary.get("tool")])
    return _matches_tokens(text, evidence_tokens)


def _scanner_failures_for(scan: models.Scan | None, evidence_tokens: set[str]) -> list[str]:
    if not scan:
        return []
    failures = (scan.result_summary or {}).get("scanner_failures") or []
    if isinstance(failures, dict):
        failures = [failures]
    if not isinstance(failures, list):
        return []
    matched = []
    for failure in failures:
        if not isinstance(failure, dict):
            continue
        text = " ".join(str(value) for value in failure.values())
        if _matches_tokens(text, evidence_tokens):
            matched.append(str(failure.get("error") or failure.get("message") or failure.get("scanner") or "scanner failure"))
    return matched


def _matches_tokens(value: str, tokens: set[str]) -> bool:
    normalized = value.lower()
    return any(token in normalized for token in tokens)


def _max_finding_severity(findings: list[dict]) -> str | None:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    severities = [_finding_severity(finding) or "unknown" for finding in findings]
    return min(severities, key=lambda item: rank.get(item, 99)) if severities else None


def _security_scan_coverage_item(
    gap_type: str,
    application: models.Application,
    repository: models.Repository,
    scan: models.Scan | None,
    has_scan_evidence: bool,
    finding_count: int,
    max_severity: str | None,
    detail: str,
) -> dict:
    return schemas.SecurityScanCoverageOut(
        gap_type=gap_type,
        application_id=application.id,
        application_name=application.name,
        repository_id=repository.id,
        repository_owner=repository.owner,
        repository_name=repository.name,
        latest_scan_id=scan.id if scan else None,
        latest_scan_status=scan.status if scan else None,
        latest_scan_tool=scan.tool if scan else None,
        latest_scan_created_at=scan.created_at if scan else None,
        has_scan_evidence=has_scan_evidence,
        finding_count=finding_count,
        max_severity=max_severity,
        detail=detail,
    ).model_dump(mode="json")
