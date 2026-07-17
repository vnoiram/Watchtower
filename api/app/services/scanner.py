from __future__ import annotations

from dataclasses import dataclass

from api.app.models import Severity

SEVERITY_ORDER = {
    Severity.unknown: 0,
    Severity.info: 1,
    Severity.low: 2,
    Severity.medium: 3,
    Severity.high: 4,
    Severity.critical: 5,
}

ALIASES = {
    "negligible": Severity.info,
    "unknown": Severity.unknown,
    "none": Severity.info,
    "low": Severity.low,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "high": Severity.high,
    "critical": Severity.critical,
}


@dataclass(frozen=True)
class NormalizedFinding:
    source: str
    vulnerability_id: str
    package_name: str
    package_version: str | None
    ecosystem: str | None
    purl: str
    severity: Severity
    fixed_version: str | None = None
    title: str | None = None
    references: tuple[str, ...] = ()


def normalize_severity(value: str | None) -> Severity:
    if not value:
        return Severity.unknown
    return ALIASES.get(value.lower(), Severity.unknown)


def merge_severity(*values: str | Severity | None) -> Severity:
    severities = [v if isinstance(v, Severity) else normalize_severity(v) for v in values]
    return max(severities or [Severity.unknown], key=lambda sev: SEVERITY_ORDER[sev])


def calculate_risk_score(severity: Severity, internet_exposed: bool, production: bool) -> float:
    score = SEVERITY_ORDER[severity] * 2.0
    if internet_exposed:
        score += 1.5
    if production:
        score += 1.0
    return min(score, 10.0)


def normalize_purl(ecosystem: str | None, name: str, version: str | None) -> str:
    package_type = {
        "npm": "npm",
        "javascript": "npm",
        "pypi": "pypi",
        "python": "pypi",
        "go": "golang",
        "maven": "maven",
        "java": "maven",
        "cargo": "cargo",
        "rust": "cargo",
    }.get((ecosystem or "").lower(), (ecosystem or "generic").lower())
    base = f"pkg:{package_type}/{name}"
    return f"{base}@{version}" if version else base


def normalize_osv_results(payload: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in payload.get("results", []):
        package = result.get("package", {})
        name = package.get("name") or "unknown"
        ecosystem = package.get("ecosystem")
        version = package.get("version")
        for vuln in result.get("vulnerabilities", []):
            severity = merge_severity(*(entry.get("score") for entry in vuln.get("severity", [])))
            fixed = None
            for affected in vuln.get("affected", []):
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        fixed = fixed or event.get("fixed")
            findings.append(
                NormalizedFinding(
                    source="osv",
                    vulnerability_id=vuln.get("id", "unknown"),
                    package_name=name,
                    package_version=version,
                    ecosystem=ecosystem,
                    purl=normalize_purl(ecosystem, name, version),
                    severity=severity,
                    fixed_version=fixed,
                    title=vuln.get("summary"),
                    references=tuple(ref.get("url") for ref in vuln.get("references", []) if ref.get("url")),
                )
            )
    return findings


def normalize_trivy_results(payload: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in payload.get("Results", []):
        ecosystem = result.get("Type")
        for vuln in result.get("Vulnerabilities", []) or []:
            name = vuln.get("PkgName", "unknown")
            version = vuln.get("InstalledVersion")
            findings.append(
                NormalizedFinding(
                    source="trivy",
                    vulnerability_id=vuln.get("VulnerabilityID", "unknown"),
                    package_name=name,
                    package_version=version,
                    ecosystem=ecosystem,
                    purl=vuln.get("PkgIdentifier", {}).get("PURL") or normalize_purl(ecosystem, name, version),
                    severity=normalize_severity(vuln.get("Severity")),
                    fixed_version=vuln.get("FixedVersion"),
                    title=vuln.get("Title"),
                    references=tuple(vuln.get("References") or ()),
                )
            )
    return findings


def normalize_grype_results(payload: dict) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for match in payload.get("matches", []) or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        name = artifact.get("name") or "unknown"
        version = artifact.get("version")
        ecosystem = artifact.get("type")
        fix_versions = (vulnerability.get("fix") or {}).get("versions") or []
        findings.append(
            NormalizedFinding(
                source="grype",
                vulnerability_id=vulnerability.get("id", "unknown"),
                package_name=name,
                package_version=version,
                ecosystem=ecosystem,
                purl=artifact.get("purl") or normalize_purl(ecosystem, name, version),
                severity=normalize_severity(vulnerability.get("severity")),
                fixed_version=fix_versions[0] if fix_versions else None,
                title=vulnerability.get("description"),
                references=tuple(vulnerability.get("urls") or ()),
            )
        )
    return findings


def normalize_gitleaks_results(payload: list | dict) -> list[dict]:
    """Shape gitleaks leaks for scan.result_summary["secrets"], as read by api.app.routers.security."""
    leaks = payload if isinstance(payload, list) else payload.get("leaks", []) or []
    findings: list[dict] = []
    for leak in leaks:
        findings.append(
            {
                "type": "secret",
                "rule_id": leak.get("RuleID"),
                "severity": Severity.high.value,
                "path": leak.get("File"),
                "title": leak.get("Description") or leak.get("RuleID") or "secret detected",
                "detail": f"{leak.get('File')}:{leak.get('StartLine')}" if leak.get("File") else None,
                "commit": leak.get("Commit"),
                "fingerprint": leak.get("Fingerprint"),
            }
        )
    return findings


_SEMGREP_SEVERITY = {
    "error": Severity.high,
    "warning": Severity.medium,
    "info": Severity.info,
}


def normalize_semgrep_results(payload: dict) -> list[dict]:
    """Shape semgrep results for scan.result_summary["sast"], as read by api.app.routers.security."""
    findings: list[dict] = []
    for result in payload.get("results", []) or []:
        extra = result.get("extra") or {}
        start_line = (result.get("start") or {}).get("line")
        severity = _SEMGREP_SEVERITY.get((extra.get("severity") or "").lower(), Severity.unknown)
        findings.append(
            {
                "type": "sast",
                "rule_id": result.get("check_id"),
                "severity": severity.value,
                "path": result.get("path"),
                "title": extra.get("message") or result.get("check_id") or "static analysis finding",
                "detail": f"{result.get('path')}:{start_line}" if result.get("path") else extra.get("message"),
            }
        )
    return findings

