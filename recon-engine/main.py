"""
Main recon pipeline module.

This module executes the full recon pipeline: DNS resolution -> port scan ->
HTTP enumeration -> technology fingerprinting -> schema-compliant JSON output.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from dns_enum import resolve_hostname
from port_scan import scan_ports
from service_enum import enumerate_http_services
from tech_fingerprint import fingerprint_all


def run_recon(hostname: str, exposure: str = "external") -> dict:
    """
    Executes the complete reconnaissance pipeline for a target hostname.

    :param hostname: Target domain or hostname to scan.
    :param exposure: Exposure type ('external' or 'internal').
    :return: Schema-compliant dictionary for one asset, or empty dict if resolution fails.
    """
    dns_result = resolve_hostname(hostname)
    if not dns_result.get("resolved"):
        print(f"Error: Unable to resolve hostname '{hostname}': {dns_result.get('error')}")
        return {}

    ip = dns_result["ip"]
    scanned_ports = scan_ports(ip)
    enriched_ports = enumerate_http_services(ip, scanned_ports)
    fingerprinted_ports = fingerprint_all(enriched_ports)

    services: list[dict] = []
    for port_info in fingerprinted_ports:
        services.append({
            "port": port_info.get("port"),
            "protocol": port_info.get("protocol"),
            "service_name": port_info.get("service_name"),
            "product": port_info.get("product", ""),
            "version": port_info.get("version", ""),
            "banner": port_info.get("banner", "")
        })

    return {
        "asset": {
            "hostname": hostname,
            "ip": ip,
            "exposure": exposure
        },
        "services": services
    }


if __name__ == "__main__":
    hostname_to_scan = "scanme.nmap.org"
    recon_result = run_recon(hostname_to_scan, exposure="external")

    output_list = [recon_result] if recon_result else []

    script_dir = Path(__file__).parent.resolve()
    output_file = script_dir / ".." / "shared" / "sample_data" / "live_recon_output.json"
    output_file = output_file.resolve()

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output_list, f, indent=2)

    total_assets = len(output_list)
    total_services = sum(len(asset.get("services", [])) for asset in output_list)

    print(f"Recon complete. Wrote {total_assets} assets with {total_services} total services to live_recon_output.json")
