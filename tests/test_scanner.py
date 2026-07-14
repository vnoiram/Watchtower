from api.app.models import Severity
from api.app.services.scanner import (
    calculate_risk_score,
    merge_severity,
    normalize_osv_results,
    normalize_purl,
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

