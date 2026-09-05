"""Data models for Risk Engine.

These classes mirror the JSON schemas defined in shared/schemas/:
- Service: Input service structure from Recon Engine (recon_output.schema.json).
- Finding: Individual vulnerability or misconfiguration result (findings_output.schema.json).
- AssetFindings: Aggregated findings output for an asset and port (findings_output.schema.json).
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Service:
    """Input service model from recon engine."""

    port: int
    protocol: str
    service_name: str
    product: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class Finding:
    """Vulnerability or misconfiguration finding result."""

    cve_id: str
    cvss_score: float
    severity: str
    risk_score: int
    priority: str
    confidence: float
    known_exploited: bool = False


@dataclass
class AssetFindings:
    """Final output representing security findings for a single asset and port."""

    asset: str
    port: int
    product: str
    version: str
    findings: List[Finding] = field(default_factory=list)
