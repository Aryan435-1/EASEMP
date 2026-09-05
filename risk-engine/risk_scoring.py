"""Risk scoring module for Risk Engine.

This module computes composite risk scores (0-100) and priority tiers for security findings.

Weighting Rationale:
- Vulnerability Danger Factor (60% total):
  - Severity (CVSS x 10): 35%
  - Known Exploited Status: 25%
  Together severity and exploitability make up 60% because they reflect how dangerous
  the vulnerability itself is.
- Organizational Context Factor (40% total):
  - Exposure (External=100, Internal=30): 25%
  - Asset Criticality (0-10 scale x 10): 15%
  Together exposure and criticality (40%) reflect business and organizational context.
"""

from models import Finding


def compute_risk_score(finding: Finding, exposure: str, asset_criticality: int) -> int:
    """Compute a 0-100 risk score using weighted vulnerability and context scores.

    Args:
        finding: Finding object containing cvss_score and known_exploited status.
        exposure: Exposure string ("external" or "internal").
        asset_criticality: Asset criticality rating from 0 to 10.

    Returns:
        An integer risk score clipped to [0, 100].
    """
    severity_score = finding.cvss_score * 10.0
    exploitability_score = 100.0 if finding.known_exploited is True else 0.0
    exposure_score = 100.0 if exposure.lower() == "external" else 30.0
    criticality_score = float(asset_criticality) * 10.0

    raw_score = round(
        0.35 * severity_score
        + 0.25 * exploitability_score
        + 0.25 * exposure_score
        + 0.15 * criticality_score
    )

    return max(0, min(100, int(raw_score)))


def assign_priority(risk_score: int) -> str:
    """Map a 0-100 risk score to a priority tier.

    Mappings:
    - 0-25   -> LOW
    - 26-50  -> MEDIUM
    - 51-75  -> HIGH
    - 76-100 -> CRITICAL

    Args:
        risk_score: Calculated risk score integer.

    Returns:
        Priority tier string ("LOW", "MEDIUM", "HIGH", "CRITICAL").
    """
    if risk_score <= 25:
        return "LOW"
    elif risk_score <= 50:
        return "MEDIUM"
    elif risk_score <= 75:
        return "HIGH"
    else:
        return "CRITICAL"


def score_finding(finding: Finding, exposure: str, asset_criticality: int) -> Finding:
    """Compute risk score and priority for a finding, updating it in place and returning it.

    Args:
        finding: Finding object to score.
        exposure: Exposure level ("external" or "internal").
        asset_criticality: Asset criticality rating (0-10).

    Returns:
        The updated Finding object with risk_score and priority populated.
    """
    risk_score = compute_risk_score(finding, exposure, asset_criticality)
    priority = assign_priority(risk_score)

    finding.risk_score = risk_score
    finding.priority = priority

    return finding
