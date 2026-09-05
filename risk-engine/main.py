"""Main pipeline orchestration for Risk Engine.

This module orchestrates the full Risk Engine pipeline:
1. Ingests recon input (matching recon_output.schema.json).
2. Performs CVE correlation (correlate_cve) and rule-based misconfiguration checks (check_misconfigurations).
3. Applies contextual risk scoring (score_finding) based on asset criticality and exposure.
4. Produces structured output (matching findings_output.schema.json).
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from cve_correlation import correlate_cve
from misconfig_checks import check_misconfigurations
from models import AssetFindings, Finding, Service
from risk_scoring import score_finding

# Asset business criticality ratings (0-10)
ASSET_CRITICALITY: Dict[str, int] = {
    "api.lab.local": 8,
    "db01.lab.local": 9,
    "vpn01.lab.local": 7,
}
DEFAULT_CRITICALITY: int = 5


def process_recon_output(recon_data: List[Dict[str, Any]]) -> List[AssetFindings]:
    """Process recon data through CVE correlation, misconfiguration checks, and risk scoring.

    Args:
        recon_data: List of asset dictionaries matching recon_output.schema.json structure.

    Returns:
        List of AssetFindings objects containing scored findings for each service with findings.
    """
    results: List[AssetFindings] = []

    for asset_item in recon_data:
        asset_info = asset_item.get("asset", {})
        hostname = asset_info.get("hostname", "")
        exposure = asset_info.get("exposure", "internal")
        asset_criticality = ASSET_CRITICALITY.get(hostname, DEFAULT_CRITICALITY)

        services = asset_item.get("services", [])
        for svc_dict in services:
            service = Service(
                port=svc_dict["port"],
                protocol=svc_dict["protocol"],
                service_name=svc_dict["service_name"],
                product=svc_dict.get("product", ""),
                version=svc_dict.get("version", ""),
                banner=svc_dict.get("banner", ""),
            )

            # Gather CVE correlation findings and rule-based misconfiguration findings
            cve_findings = correlate_cve(service.product, service.version)
            misconfig_findings = check_misconfigurations(service, exposure)
            combined_findings: List[Finding] = cve_findings + misconfig_findings

            # Apply risk scoring to all findings
            for finding in combined_findings:
                score_finding(finding, exposure, asset_criticality)

            # Only record services that yielded findings
            if combined_findings:
                asset_finding = AssetFindings(
                    asset=hostname,
                    port=service.port,
                    product=service.product,
                    version=service.version,
                    findings=combined_findings,
                )
                results.append(asset_finding)

    return results


def findings_to_dict(asset_findings: AssetFindings) -> Dict[str, Any]:
    """Convert an AssetFindings object into a JSON-serializable dictionary matching findings_output.schema.json.

    Args:
        asset_findings: AssetFindings dataclass instance.

    Returns:
        Plain dictionary matching findings_output.schema.json structure.
    """
    return {
        "asset": asset_findings.asset,
        "port": asset_findings.port,
        "product": asset_findings.product,
        "version": asset_findings.version,
        "findings": [
            {
                "cve_id": finding.cve_id,
                "cvss_score": finding.cvss_score,
                "severity": finding.severity,
                "known_exploited": finding.known_exploited,
                "risk_score": finding.risk_score,
                "priority": finding.priority,
                "confidence": finding.confidence,
            }
            for finding in asset_findings.findings
        ],
    }


if __name__ == "__main__":
    base_dir = Path(__file__).parent
    input_path = base_dir.parent / "shared" / "sample_data" / "sample_recon_output.json"
    output_path = base_dir / "findings_output.json"

    with open(input_path, "r", encoding="utf-8") as f:
        recon_data = json.load(f)

    asset_findings_list = process_recon_output(recon_data)
    dict_results = [findings_to_dict(af) for af in asset_findings_list]

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dict_results, f, indent=2)

    total_assets = len(recon_data)
    total_findings = sum(len(af.findings) for af in asset_findings_list)
    print(f"Processed {total_assets} assets, found {total_findings} findings")
