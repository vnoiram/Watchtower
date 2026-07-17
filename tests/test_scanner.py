from api.app.models import Severity
from api.app.services.scanner import (
    calculate_risk_score,
    merge_severity,
    normalize_gitleaks_results,
    normalize_grype_results,
    normalize_osv_results,
    normalize_purl,
    normalize_semgrep_results,
    normalize_trivy_results,
)


def test_normalize_purl_maps_common_ecosystems() -> None:
    assert normalize_purl("python", "fastapi", "0.111.0") == "pkg:pypi/fastapi@0.111.0"
    assert normalize_purl("npm", "@scope/pkg", "1.2.3") == "pkg:npm/@scope/pkg@1.2.3"


def test_merge_severity_keeps_highest() -> None:
    assert merge_severity("low", "critical", "medium") == Severity.critical


def test_risk_score_accounts_for_exposure_and_production() -> None:
    assert calculate_risk_score(Severity.high, internet_exposed=True, production=True) == 10.0


def test_normalize_osv_results() -> None:
    payload = {
        "results": [
            {
                "package": {"name": "demo", "ecosystem": "PyPI", "version": "1.0.0"},
                "vulnerabilities": [
                    {
                        "id": "GHSA-123",
                        "summary": "demo issue",
                        "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                        "references": [{"url": "https://example.test"}],
                    }
                ],
            }
        ]
    }
    findings = normalize_osv_results(payload)
    assert findings[0].source == "osv"
    assert findings[0].severity == Severity.high


def test_normalize_trivy_results() -> None:
    payload = {
        "Results": [
            {
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "left-pad",
                        "InstalledVersion": "1.0.0",
                        "Severity": "CRITICAL",
                        "FixedVersion": "1.0.1",
                    }
                ],
            }
        ]
    }
    findings = normalize_trivy_results(payload)
    assert findings[0].purl == "pkg:npm/left-pad@1.0.0"
    assert findings[0].fixed_version == "1.0.1"


def test_normalize_grype_results() -> None:
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-0002",
                    "severity": "High",
                    "description": "demo grype finding",
                    "urls": ["https://example.test/advisory"],
                    "fix": {"versions": ["2.0.1"], "state": "fixed"},
                },
                "artifact": {
                    "name": "left-pad",
                    "version": "1.0.0",
                    "type": "npm",
                    "purl": "pkg:npm/left-pad@1.0.0",
                },
            }
        ]
    }
    findings = normalize_grype_results(payload)
    assert findings[0].source == "grype"
    assert findings[0].vulnerability_id == "CVE-2026-0002"
    assert findings[0].purl == "pkg:npm/left-pad@1.0.0"
    assert findings[0].severity == Severity.high
    assert findings[0].fixed_version == "2.0.1"


def test_normalize_gitleaks_results() -> None:
    payload = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "config.py",
            "StartLine": 12,
            "Commit": "abc123",
            "Fingerprint": "config.py:generic-api-key:12",
        }
    ]
    findings = normalize_gitleaks_results(payload)
    assert findings[0]["type"] == "secret"
    assert findings[0]["rule_id"] == "generic-api-key"
    assert findings[0]["path"] == "config.py"
    assert findings[0]["severity"] == Severity.high.value


def test_normalize_semgrep_results() -> None:
    payload = {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-eval",
                "path": "app/main.py",
                "start": {"line": 42},
                "extra": {"message": "Detected use of eval", "severity": "ERROR"},
            }
        ]
    }
    findings = normalize_semgrep_results(payload)
    assert findings[0]["type"] == "sast"
    assert findings[0]["rule_id"] == "python.lang.security.audit.dangerous-eval"
    assert findings[0]["path"] == "app/main.py"
    assert findings[0]["detail"] == "app/main.py:42"

