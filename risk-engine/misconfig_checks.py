"""Misconfiguration checks module for Risk Engine.

This module provides deterministic, rule-based security configuration checks
that operate independently of any CVE vulnerability database.
"""

from typing import List
from models import Finding, Service


def check_misconfigurations(service: Service, exposure: str) -> List[Finding]:
    """Check a service and asset exposure against rule-based misconfiguration heuristics.

    Args:
        service: Service object containing port, protocol, service_name, product, etc.
        exposure: Asset exposure level ("internal" or "external").

    Returns:
        List of Finding objects corresponding to any detected misconfigurations.
    """
    findings: List[Finding] = []
    exposure_lower = exposure.lower()
    service_name_lower = service.service_name.lower()

    # Rule 1: Database exposed to external network
    if service_name_lower in ("mysql", "postgresql", "mongodb") and exposure_lower == "external":
        findings.append(
            Finding(
                cve_id="MISCONFIG-DB-EXPOSED",
                cvss_score=8.0,
                severity="HIGH",
                known_exploited=False,
                risk_score=0,
                priority="",
                confidence=0.75,
            )
        )

    # Rule 2: Legacy / insecure protocols enabled (Telnet: 23, FTP: 21)
    if service.port in (23, 21):
        findings.append(
            Finding(
                cve_id="MISCONFIG-LEGACY-PROTOCOL",
                cvss_score=6.0,
                severity="MEDIUM",
                known_exploited=False,
                risk_score=0,
                priority="",
                confidence=0.75,
            )
        )

    # Rule 3: Common administrative ports exposed externally (8080, 8443, 9090)
    if service.port in (8080, 8443, 9090) and exposure_lower == "external":
        findings.append(
            Finding(
                cve_id="MISCONFIG-ADMIN-EXPOSED",
                cvss_score=7.0,
                severity="HIGH",
                known_exploited=False,
                risk_score=0,
                priority="",
                confidence=0.75,
            )
        )

    return findings
