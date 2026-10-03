"""
Technology fingerprinting module.

This module normalizes raw Nmap/HTTP data into consistent product/version fields,
preferring Nmap's own detection when available and falling back to parsing HTTP
Server headers when it isn't.
"""

import json
import re
from typing import Any, Dict, List


def fingerprint_service(port_dict: dict) -> dict:
    """
    Fingerprints service details for a single port dictionary.

    :param port_dict: Enriched port dictionary containing product, version, banner, and headers.
    :return: Updated port dictionary with product and version fields populated.
    """
    updated_dict = dict(port_dict)

    product = updated_dict.get("product", "")
    version = updated_dict.get("version", "")

    # If port_dict already has a non-empty product and version, trust Nmap's detection
    if product and version:
        return updated_dict

    # If product/version are empty/missing, look for "Server" header in headers dict
    headers = updated_dict.get("headers")
    if isinstance(headers, dict):
        server_header = None
        for key, val in headers.items():
            if key.lower() == "server":
                server_header = str(val)
                break

        if server_header:
            pattern = r'([A-Za-z\-]+)/([\d\.]+)'
            match = re.search(pattern, server_header)
            if match:
                updated_dict["product"] = match.group(1)
                updated_dict["version"] = match.group(2)

    return updated_dict


def fingerprint_all(enriched_ports: list[dict]) -> list[dict]:
    """
    Applies technology fingerprinting to a list of enriched port dictionaries.

    :param enriched_ports: List of enriched port dictionaries.
    :return: List of fingerprinted port dictionaries.
    """
    return [fingerprint_service(port_dict) for port_dict in enriched_ports]


if __name__ == "__main__":
    from port_scan import scan_ports
    from service_enum import enumerate_http_services

    target_ip = "45.33.32.156"
    print(f"Running full recon chain against {target_ip}...")
    scanned_ports = scan_ports(target_ip)
    enriched_ports = enumerate_http_services(target_ip, scanned_ports)
    fingerprinted_ports = fingerprint_all(enriched_ports)
    print(json.dumps(fingerprinted_ports, indent=2))
