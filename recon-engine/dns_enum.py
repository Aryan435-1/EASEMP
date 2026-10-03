"""
Stage 1 of the recon pipeline: Resolving a target hostname to a scannable IP address.
"""

import json
import socket
from typing import Any, Dict, List
import dns.resolver


def resolve_hostname(hostname: str) -> Dict[str, Any]:
    """
    Resolves IPv4 A records for a given hostname.

    :param hostname: Target domain name or hostname to resolve.
    :return: A dictionary containing resolution status, primary IP, all resolved IPs, or error details.
    """
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        all_ips: List[str] = [str(rdata) for rdata in answers]
        primary_ip = all_ips[0] if all_ips else None
        return {
            "hostname": hostname,
            "ip": primary_ip,
            "all_ips": all_ips,
            "resolved": True
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
        return {
            "hostname": hostname,
            "ip": None,
            "all_ips": [],
            "resolved": False,
            "error": str(e)
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "ip": None,
            "all_ips": [],
            "resolved": False,
            "error": str(e)
        }


if __name__ == "__main__":
    result = resolve_hostname("scanme.nmap.org")
    print(json.dumps(result, indent=2))
