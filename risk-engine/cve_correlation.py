"""CVE correlation module for Risk Engine.

This module provides CVE lookup logic based on product name and version.
Note: MOCK_CVE_DB is a mock database for demonstration and testing purposes.
It will later be replaced by a real CVE data source (such as NVD API or a local database),
but the function signature for correlate_cve will remain unchanged so downstream pipeline
components require no modification.
"""

from typing import Any, Dict, List
from models import Finding


MOCK_CVE_DB: Dict[str, List[Dict[str, Any]]] = {
    "nginx:1.18.0": [
        {
            "cve_id": "CVE-2021-23017",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "known_exploited": False,
        }
    ],
    "mysql:5.7.31": [
        {
            "cve_id": "CVE-2020-14812",
            "cvss_score": 4.7,
            "severity": "MEDIUM",
            "known_exploited": False,
        }
    ],
    "apache:2.4.29": [
        {
            "cve_id": "CVE-2021-41773",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "known_exploited": True,
        }
    ],
}


def correlate_cve(product: str, version: str) -> List[Finding]:
    """Correlate a product and version against CVE records to identify potential vulnerabilities.

    Args:
        product: The product name (e.g., 'nginx', 'Apache').
        version: The version string (e.g., '1.18.0').

    Returns:
        A list of Finding objects with CVE data populated and placeholder risk parameters.
    """
    key = f"{product.lower()}:{version}"
    cve_entries = MOCK_CVE_DB.get(key, [])

    findings: List[Finding] = []
    for entry in cve_entries:
        finding = Finding(
            cve_id=entry["cve_id"],
            cvss_score=entry["cvss_score"],
            severity=entry["severity"],
            known_exploited=entry["known_exploited"],
            risk_score=0,
            priority="",
            confidence=0.9,
        )
        findings.append(finding)

    return findings
