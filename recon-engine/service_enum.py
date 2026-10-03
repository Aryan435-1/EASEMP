"""
Service enumeration module.

This module enriches HTTP/HTTPS services with raw response headers,
which technology fingerprinting will use for more precise detection.
"""

import json
from typing import Any, Dict, List
import requests


def fetch_http_headers(ip: str, port: int) -> dict:
    """
    Fetches raw HTTP headers for a target IP and port.

    :param ip: Target IP address.
    :param port: Target port number.
    :return: Dictionary containing status code, headers, reachability, or error info.
    """
    url = f"http://{ip}:{port}/"
    try:
        response = requests.get(url, timeout=5)
        return {
            "port": port,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "reachable": True,
        }
    except Exception as e:
        print(f"HTTP fetch failed for port {port}: {e}")
        return {
            "port": port,
            "status_code": None,
            "headers": {},
            "reachable": False,
            "error": str(e),
        }


def enumerate_http_services(ip: str, open_ports: list[dict]) -> list[dict]:
    """
    Enriches open port details by fetching HTTP headers for HTTP/HTTPS services.

    :param ip: Target IP address.
    :param open_ports: List of open port dictionaries from scan_ports.
    :return: Enriched list of port dictionaries.
    """
    enriched_ports: list[dict] = []
    for port_dict in open_ports:
        service_name = str(port_dict.get("service_name", "")).lower()
        if service_name in ["http", "https"]:
            port = port_dict["port"]
            http_info = fetch_http_headers(ip, port)
            enriched_port = {**port_dict, **http_info}
            enriched_ports.append(enriched_port)
        else:
            enriched_ports.append(port_dict.copy())
    return enriched_ports


if __name__ == "__main__":
    from port_scan import scan_ports

    target_ip = "45.33.32.156"
    print(f"Scanning target {target_ip} and enumerating HTTP services...")
    ports = scan_ports(target_ip)
    enriched = enumerate_http_services(target_ip, ports)
    print(json.dumps(enriched, indent=2))
