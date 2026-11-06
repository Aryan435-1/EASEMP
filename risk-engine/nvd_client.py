"""
NVD CVE API 2.0 client — fetch and parse only.

This module implements the cache-aside *miss* path: when ``nvd_cache`` has no
fresh data for a (product, version) pair, the caller should use
``fetch_cves_for_cpe`` here to retrieve live results and then hand them back
to ``nvd_cache.store_cves_in_cache``.

Return contract
---------------
``fetch_cves_for_cpe`` returns a non-empty list only when NVD reports at least
one scoreable CVE.  An empty list ``[]`` is returned only when NVD genuinely
reports zero CVEs for the CPE.  On any network or API failure the function
raises :class:`NVDError` and never returns ``[]``, so callers can safely cache
an empty list (negative result) but must not cache anything after an
exception.
"""

import json
import logging
import os
import sys
import time
from pathlib import Path
from urllib.parse import quote

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

# Load .env from the same directory as this file.  The file is never opened,
# read, printed, or logged here; os.getenv is used inside functions only.
load_dotenv(Path(__file__).resolve().parent / ".env")

NVD_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

logger: logging.Logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class NVDError(Exception):
    """Raised when the NVD API cannot be queried reliably."""


# ---------------------------------------------------------------------------
# Rate-limiting
# ---------------------------------------------------------------------------

MIN_INTERVAL_WITH_KEY: float = 1.0   # 50 req / 30 s ≈ 0.6 s; use 1.0 s
MIN_INTERVAL_NO_KEY: float = 6.0     # 5 req / 30 s = 6.0 s

_last_request: float = 0.0


def _pace() -> None:
    """Sleep just long enough to respect NVD's per-key rate limit.

    Uses ``time.monotonic`` so wall-clock adjustments (DST, NTP) do not
    produce negative sleep values.  Must be called before *every* HTTP
    attempt, retries included.
    """
    global _last_request

    key: str = (os.getenv("NVD_API_KEY") or "").strip()
    interval: float = MIN_INTERVAL_WITH_KEY if key else MIN_INTERVAL_NO_KEY

    elapsed: float = time.monotonic() - _last_request
    wait: float = interval - elapsed
    if wait > 0:
        time.sleep(wait)
    _last_request = time.monotonic()


# ---------------------------------------------------------------------------
# Low-level HTTP helper
# ---------------------------------------------------------------------------


def _get_json(url: str) -> dict:
    """Fetch *url* and return the parsed JSON body.

    Retries up to 4 attempts total, honouring NVD's ``Retry-After`` header
    and sleeping before every attempt (including the first) via :func:`_pace`.

    Parameters
    ----------
    url:
        Fully-formed NVD API URL including query parameters.

    Returns
    -------
    dict
        Parsed JSON response body.

    Raises
    ------
    NVDError
        On a terminal HTTP error (404, unexpected status) or after exhausting
        all retry attempts.
    """
    key: str = (os.getenv("NVD_API_KEY") or "").strip()
    headers: dict[str, str] = {"apiKey": key} if key else {}

    max_attempts: int = 4
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        _pace()

        try:
            resp: requests.Response = requests.get(
                url, headers=headers, timeout=30
            )
        except requests.RequestException as exc:
            logger.warning(
                "NVD request error (attempt %d/%d): %s", attempt, max_attempts, exc
            )
            last_exc = exc
            _sleep_for_retry(attempt, retry_after=None)
            continue

        # --- 200 OK --------------------------------------------------------
        if resp.status_code == 200:
            try:
                return resp.json()
            except (json.JSONDecodeError, ValueError):
                # NVD occasionally serves an HTML rate-limit page with 200.
                logger.warning(
                    "NVD returned non-JSON body (attempt %d/%d); retrying.",
                    attempt,
                    max_attempts,
                )
                last_exc = NVDError("NVD returned a non-JSON 200 response")
                _sleep_for_retry(attempt, retry_after=None)
                continue

        # --- 404 — do not retry --------------------------------------------
        if resp.status_code == 404:
            msg_header: str = resp.headers.get("message", "")
            if "api" in msg_header.lower() or "key" in msg_header.lower():
                raise NVDError(
                    f"NVD rejected the API key - check NVD_API_KEY in "
                    f"risk-engine/.env (the key must be activated and is "
                    f"case sensitive). NVD message: {msg_header!r}"
                )
            raise NVDError(
                f"NVD returned 404 (invalid parameter). "
                f"NVD message: {msg_header!r}"
            )

        # --- Retryable server-side errors -----------------------------------
        if resp.status_code in {403, 429, 500, 502, 503, 504}:
            retry_after_raw: str | None = resp.headers.get("Retry-After")
            retry_after: float | None = None
            if retry_after_raw is not None:
                try:
                    retry_after = float(retry_after_raw)
                except ValueError:
                    pass
            logger.warning(
                "NVD returned %d (attempt %d/%d); retrying.",
                resp.status_code,
                attempt,
                max_attempts,
            )
            last_exc = NVDError(f"NVD HTTP {resp.status_code}")
            _sleep_for_retry(attempt, retry_after=retry_after)
            continue

        # --- Unexpected status ----------------------------------------------
        raise NVDError(
            f"Unexpected NVD response status: {resp.status_code}"
        )

    raise NVDError(
        f"NVD API unreachable after {max_attempts} attempts. "
        f"Last error: {last_exc}"
    )


def _sleep_for_retry(attempt: int, retry_after: float | None) -> None:
    """Sleep before a retry attempt.

    Uses the ``Retry-After`` header value when available, otherwise backs off
    as ``6 * attempt`` seconds.
    """
    wait: float = retry_after if retry_after is not None else 6.0 * attempt
    logger.debug("Waiting %.1f s before retry %d.", wait, attempt + 1)
    time.sleep(wait)


# ---------------------------------------------------------------------------
# CVE parsing
# ---------------------------------------------------------------------------

_KNOWN_SEVERITIES: frozenset[str] = frozenset(
    {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
)

_METRIC_PREFERENCE: list[str] = [
    "cvssMetricV31",
    "cvssMetricV40",
    "cvssMetricV30",
    "cvssMetricV2",
]


def _severity_from_score(score: float) -> str:
    """Derive a severity band from a numeric CVSS base score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _parse_cve(cve: dict) -> dict | None:
    """Parse a single NVD CVE record into a flat dict, or return ``None``.

    Metric version preference
    -------------------------
    NVD may attach scores from multiple CVSS versions.  We prefer the most
    recent standard in the order v3.1 > v4.0 > v3.0 > v2 because v3.1 and
    v4.0 reflect the current severity model, while v2 is legacy.  Within the
    chosen metric list we prefer the entry flagged ``"type": "Primary"``
    (the NVD-assigned score) over any secondary/vendor entry.

    CVEs with no score at all (status *Awaiting Analysis* or *Undergoing
    Analysis*) are skipped by returning ``None`` because the downstream risk
    formula requires a numeric CVSS score.

    Parameters
    ----------
    cve:
        The ``item["cve"]`` sub-dict from a NVD API response.

    Returns
    -------
    dict
        Keys: ``cve_id``, ``cvss_score``, ``severity``, ``known_exploited``.
    None
        When no CVSS metric is present.
    """
    metrics: dict = cve.get("metrics", {})

    chosen_entry: dict | None = None
    for metric_key in _METRIC_PREFERENCE:
        metric_list: list[dict] = metrics.get(metric_key, [])
        if not metric_list:
            continue
        # Prefer Primary; fall back to the first entry.
        primary = next(
            (e for e in metric_list if e.get("type") == "Primary"), None
        )
        chosen_entry = primary if primary is not None else metric_list[0]
        break

    if chosen_entry is None:
        return None  # CVE awaiting analysis — skip.

    cvss_data: dict = chosen_entry.get("cvssData", {})
    raw_score = cvss_data.get("baseScore")
    if raw_score is None:
        return None

    cvss_score: float = float(raw_score)

    # baseSeverity lives on cvssData for v3.x/v4.x, on the entry itself for v2.
    raw_severity: str | None = cvss_data.get("baseSeverity") or chosen_entry.get(
        "baseSeverity"
    )
    severity: str = (raw_severity or "").upper()
    if severity not in _KNOWN_SEVERITIES:
        severity = _severity_from_score(cvss_score)

    known_exploited: bool = bool(cve.get("cisaExploitAdd"))

    return {
        "cve_id": cve["id"],
        "cvss_score": cvss_score,
        "severity": severity,
        "known_exploited": known_exploited,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def fetch_cves_for_cpe(cpe_name: str) -> list[dict]:
    """Fetch all scoreable CVEs for *cpe_name* from the NVD CVE API 2.0.

    Pages through the NVD result set (up to 2 000 items per page) and
    returns a de-duplicated, sorted list of CVE records.

    Flags ``isVulnerable`` and ``noRejected`` are appended as valueless query
    parameters (NVD requires them to appear in the URL without ``=value``).

    Return contract
    ---------------
    * Returns ``[]`` only when NVD genuinely reports zero CVEs for the CPE.
    * Raises :class:`NVDError` on any network or API failure — never returns
      ``[]`` on a failure — so callers can safely cache an empty list but must
      not cache anything after an exception.

    Parameters
    ----------
    cpe_name:
        A CPE 2.3 formatted string, e.g.
        ``"cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"``.

    Returns
    -------
    list[dict]
        Each dict contains keys ``cve_id``, ``cvss_score``, ``severity``, and
        ``known_exploited``.  Sorted by ``(-cvss_score, cve_id)``.

    Raises
    ------
    ValueError
        When *cpe_name* does not start with ``"cpe:2.3:"``.
    NVDError
        On any API or network failure.
    """
    if not cpe_name.startswith("cpe:2.3:"):
        raise ValueError(
            f"cpe_name must start with 'cpe:2.3:'; got {cpe_name!r}"
        )

    results_per_page: int = 2000
    start: int = 0
    total_results: int | None = None  # populated from the first response
    seen_ids: set[str] = set()
    all_cves: list[dict] = []
    skipped: int = 0

    while True:
        url: str = (
            f"{NVD_URL}"
            f"?cpeName={quote(cpe_name, safe=':*')}"
            f"&isVulnerable"
            f"&noRejected"
            f"&resultsPerPage={results_per_page}"
            f"&startIndex={start}"
        )

        data: dict = _get_json(url)

        if total_results is None:
            total_results = int(data.get("totalResults", 0))
            logger.info(
                "NVD reports %d total results for %r.", total_results, cpe_name
            )

        vulnerabilities: list[dict] = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break  # No more pages.

        for item in vulnerabilities:
            cve_raw: dict = item.get("cve", {})
            parsed = _parse_cve(cve_raw)
            if parsed is None:
                skipped += 1
                continue
            cve_id: str = parsed["cve_id"]
            if cve_id in seen_ids:
                continue
            seen_ids.add(cve_id)
            all_cves.append(parsed)

        start += len(vulnerabilities)
        if total_results is not None and start >= total_results:
            break

    if skipped:
        logger.info(
            "Skipped %d CVE(s) with no CVSS score for %r.", skipped, cpe_name
        )

    all_cves.sort(key=lambda c: (-c["cvss_score"], c["cve_id"]))
    return all_cves


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    cpe: str = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*"
    )

    try:
        cves: list[dict] = fetch_cves_for_cpe(cpe)
    except NVDError as exc:
        print(f"NVDError: {exc}")
        sys.exit(1)

    exploited: int = sum(1 for c in cves if c["known_exploited"])
    severity_counts: dict[str, int] = {}
    for c in cves:
        sev: str = c["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"Total CVEs      : {len(cves)}")
    print(f"Known exploited : {exploited}")
    print("Severity counts :")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count: int = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev:<8} {count}")
    print("\nTop 5 CVEs:")
    for entry in cves[:5]:
        print(json.dumps(entry))
