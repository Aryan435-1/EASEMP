"""
Stage 2 of the recon pipeline: Performing a light, scoped port scan (top 100 ports only)
against an authorized target.

Note: Nmap must be installed on the host system and available on the system PATH for
python-nmap to work properly.
"""

import json
from typing import Any, Dict, List
import nmap


def scan_ports(ip: str) -> List[Dict[str, Any]]:
    """
    Scans the top 100 ports for a target IP address using nmap service/version detection.

    :param ip: Target IP address to scan.
    :return: List of dictionaries representing open TCP ports and detected service details.
    """
    open_ports: List[Dict[str, Any]] = []

    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, arguments='-sV -T3 --top-ports 100')

        if ip in scanner.all_hosts():
            host_data = scanner[ip]
            if 'tcp' in host_data:
                for port, port_data in host_data['tcp'].items():
                    if port_data.get('state') == 'open':
                        service_name = port_data.get('name', '') or ''
                        product = port_data.get('product', '') or ''
                        version = port_data.get('version', '') or ''

                        banner = f"{product} {version}".strip() if product else ""

                        open_ports.append({
                            "port": int(port),
                            "protocol": "tcp",
                            "service_name": service_name,
                            "product": product,
                            "version": version,
                            "banner": banner
                        })

    except Exception:
        # Catch exceptions if nmap binary is missing, permission fails, or scan errors out
        return []

    return open_ports


if __name__ == "__main__":
    target_ip = "45.33.32.156"
    print("Scanning scanme.nmap.org — this may take 15-30 seconds...")
    results = scan_ports(target_ip)
    print(json.dumps(results, indent=2))
