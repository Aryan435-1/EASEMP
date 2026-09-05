"""Edge case test suite for Risk Engine pipeline.

Tests process_recon_output with various boundary conditions and edge cases:
1. Service with empty product and empty version.
2. Service with known product but unknown version.
3. Asset with unknown hostname (DEFAULT_CRITICALITY fallback).
4. Asset with mixed-case exposure string ('External').
5. Asset with empty services list.
"""

from typing import Tuple
from main import process_recon_output


def test_empty_product_and_version() -> Tuple[bool, str]:
    desc = "Service with empty product and version returns zero findings without crashing"
    try:
        recon_data = [
            {
                "asset": {
                    "hostname": "test.local",
                    "ip": "10.0.0.1",
                    "exposure": "internal",
                },
                "services": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "service_name": "http",
                        "product": "",
                        "version": "",
                        "banner": "",
                    }
                ],
            }
        ]
        results = process_recon_output(recon_data)
        assert len(results) == 0, f"Expected 0 results, got {len(results)}"
        return True, f"PASS: {desc}"
    except Exception as e:
        return False, f"FAIL: {desc} - {e}"


def test_unknown_version() -> Tuple[bool, str]:
    desc = "Known product with unknown version returns zero CVE findings without crashing"
    try:
        recon_data = [
            {
                "asset": {
                    "hostname": "test.local",
                    "ip": "10.0.0.1",
                    "exposure": "internal",
                },
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service_name": "https",
                        "product": "nginx",
                        "version": "99.99.99",
                        "banner": "",
                    }
                ],
            }
        ]
        results = process_recon_output(recon_data)
        assert len(results) == 0, f"Expected 0 results, got {len(results)}"
        return True, f"PASS: {desc}"
    except Exception as e:
        return False, f"FAIL: {desc} - {e}"


def test_unknown_hostname_criticality_fallback() -> Tuple[bool, str]:
    desc = "Unknown hostname falls back to DEFAULT_CRITICALITY and scores findings correctly"
    try:
        recon_data = [
            {
                "asset": {
                    "hostname": "unknown.lab.local",
                    "ip": "10.0.0.2",
                    "exposure": "external",
                },
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service_name": "https",
                        "product": "Apache",
                        "version": "2.4.29",
                        "banner": "",
                    }
                ],
            }
        ]
        results = process_recon_output(recon_data)
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        finding = results[0].findings[0]
        assert finding.risk_score == 84, f"Expected risk_score 84, got {finding.risk_score}"
        return True, f"PASS: {desc}"
    except Exception as e:
        return False, f"FAIL: {desc} - {e}"


def test_mixed_case_exposure() -> Tuple[bool, str]:
    desc = "Mixed-case exposure 'External' is handled case-insensitively as external exposure"
    try:
        recon_data = [
            {
                "asset": {
                    "hostname": "api.lab.local",
                    "ip": "192.168.56.20",
                    "exposure": "External",
                },
                "services": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "service_name": "https",
                        "product": "nginx",
                        "version": "1.18.0",
                        "banner": "",
                    }
                ],
            }
        ]
        results = process_recon_output(recon_data)
        assert len(results) == 1, f"Expected 1 result, got {len(results)}"
        finding = results[0].findings[0]
        assert finding.risk_score == 71, f"Expected risk_score 71, got {finding.risk_score}"
        return True, f"PASS: {desc}"
    except Exception as e:
        return False, f"FAIL: {desc} - {e}"


def test_empty_services_list() -> Tuple[bool, str]:
    desc = "Completely empty services list returns zero AssetFindings entries without crashing"
    try:
        recon_data = [
            {
                "asset": {
                    "hostname": "test.local",
                    "ip": "10.0.0.4",
                    "exposure": "internal",
                },
                "services": [],
            }
        ]
        results = process_recon_output(recon_data)
        assert len(results) == 0, f"Expected 0 results, got {len(results)}"
        return True, f"PASS: {desc}"
    except Exception as e:
        return False, f"FAIL: {desc} - {e}"


def run_all_tests():
    tests = [
        test_empty_product_and_version,
        test_unknown_version,
        test_unknown_hostname_criticality_fallback,
        test_mixed_case_exposure,
        test_empty_services_list,
    ]

    passed_count = 0
    total_tests = len(tests)

    for test in tests:
        passed, message = test()
        print(message)
        if passed:
            passed_count += 1

    print(f"\n{passed_count}/{total_tests} tests passed")


if __name__ == "__main__":
    run_all_tests()
