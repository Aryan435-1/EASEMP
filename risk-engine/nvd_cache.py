"""
NVD vulnerability local cache — cache-aside pattern.

Local lookups are checked first; only a cache miss (never seen, or stale)
should trigger a live NVD API call, to be added in the next stage.

Return-value contract for get_cached_cves:
  None  → "ask NVD" (product/version was never looked up, or the cached
          entry has expired beyond CACHE_TTL_DAYS).
  []    → "NVD was asked and has no CVEs for this product/version."
  [...]  → list of CVE dicts that were previously stored from NVD.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ---------------------------------------------------------------------------
# Database bootstrap
# ---------------------------------------------------------------------------

DB_PATH: Path = Path(__file__).resolve().parent / "nvd_cache.db"
engine = create_engine(f"sqlite:///{DB_PATH.as_posix()}")

Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

CACHE_TTL_DAYS: int = 7

#: Sentinel stored in the cache to record that NVD was queried and returned
#: zero CVEs.  Distinguishes "never queried" (no rows) from "queried, none
#: found" (one marker row).
NO_CVE_MARKER: str = "NONE"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC time as a *naive* datetime (no tzinfo).

    ``datetime.utcnow()`` is deprecated since Python 3.12; this wrapper uses
    the recommended ``datetime.now(timezone.utc)`` and strips the tzinfo so
    that all stored and compared timestamps are consistently naive UTC.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _key(product: str, version: str) -> tuple[str, str]:
    """Normalise a (product, version) pair for consistent cache keying.

    Product names are lowercased and stripped; versions are only stripped so
    that case differences (e.g. ``"OpenSSL"`` vs ``"openssl"``) never produce
    duplicate cache entries, while version strings like ``"1.0.0a"`` remain
    intact.
    """
    return (product.strip().lower(), version.strip())


# ---------------------------------------------------------------------------
# ORM model
# ---------------------------------------------------------------------------


class CachedCVE(Base):
    """One row per (product, version, cve_id) triplet stored in the cache."""

    __tablename__ = "cached_cves"

    id: int = Column(Integer, primary_key=True, autoincrement=True)
    product: str = Column(String, nullable=False)
    version: str = Column(String, nullable=False)
    cve_id: str = Column(String, nullable=False)
    cvss_score: float | None = Column(Float, nullable=True)
    severity: str | None = Column(String, nullable=True)
    known_exploited: bool = Column(Boolean, default=False)
    cached_at: datetime = Column(DateTime, nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("product", "version", "cve_id", name="uq_cached_cve"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<CachedCVE product={self.product!r} version={self.version!r} "
            f"cve_id={self.cve_id!r} cvss={self.cvss_score}>"
        )


# ---------------------------------------------------------------------------
# Initialisation — called once at module level so the table always exists
# ---------------------------------------------------------------------------


def init_cache_db() -> None:
    """Create the ``cached_cves`` table (and any future tables) if absent.

    Safe to call multiple times; SQLAlchemy's ``create_all`` is idempotent
    when ``checkfirst=True`` (the default).
    """
    Base.metadata.create_all(bind=engine)


# Run immediately so the table is ready as soon as the module is imported.
init_cache_db()

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_cached_cves(product: str, version: str) -> list[dict] | None:
    """Return cached CVE data for *product*/*version*, or ``None`` on a miss.

    TTL note
    --------
    NVD continuously publishes new CVEs for existing software, so a
    product/version pair queried once and cached forever would silently miss
    any vulnerability disclosed after the cache was written.  The TTL
    (``CACHE_TTL_DAYS``) forces periodic re-validation rather than treating
    any cached result as permanently authoritative.

    Parameters
    ----------
    product:
        The software product name (case-insensitive, whitespace-stripped).
    version:
        The software version string (whitespace-stripped, case-preserved).

    Returns
    -------
    None
        The pair has never been looked up, or every cached row is older than
        ``CACHE_TTL_DAYS`` days (treat as stale → caller should query NVD).
    list[dict]
        A (possibly empty) list of CVE records.  An empty list means NVD was
        previously queried and returned no CVEs for this pair; the caller
        should *not* re-query NVD until the TTL expires.
    """
    norm_product, norm_version = _key(product, version)
    session = SessionLocal()
    try:
        rows: list[CachedCVE] = (
            session.query(CachedCVE)
            .filter(
                CachedCVE.product == norm_product,
                CachedCVE.version == norm_version,
            )
            .all()
        )

        # No rows at all → never looked up.
        if not rows:
            return None

        # TTL check — read at call time so tests can patch the module global.
        cutoff: datetime = _utcnow() - timedelta(days=CACHE_TTL_DAYS)

        # If *every* row is beyond the TTL window, treat the entry as stale.
        if all(row.cached_at < cutoff for row in rows):
            return None

        # At least one row is within the TTL → entry is fresh.
        # Filter out the negative-cache sentinel before returning.
        results: list[dict] = [
            {
                "cve_id": row.cve_id,
                "cvss_score": row.cvss_score,
                "severity": row.severity,
                "known_exploited": row.known_exploited,
            }
            for row in rows
            if row.cve_id != NO_CVE_MARKER
        ]
        return results

    finally:
        session.close()


def store_cves_in_cache(
    product: str, version: str, cve_list: list[dict]
) -> None:
    """Persist *cve_list* for *product*/*version* in the local SQLite cache.

    The operation is performed inside a single transaction:

    1. Delete all existing rows for the normalised (product, version) pair so
       that a refresh replaces stale data without violating the unique
       constraint on ``(product, version, cve_id)``.
    2. Insert one :class:`CachedCVE` row per entry in *cve_list*.
       Duplicate ``cve_id`` values within the list are silently skipped.

    Negative caching
    ----------------
    If *cve_list* is empty, a single sentinel row with
    ``cve_id=NO_CVE_MARKER`` is inserted.  This records that NVD was
    successfully contacted and returned zero results, preventing unnecessary
    repeat queries for the duration of the TTL.

    Parameters
    ----------
    product:
        The software product name.
    version:
        The software version string.
    cve_list:
        List of CVE dicts, each expected to have the keys ``cve_id``,
        ``cvss_score``, ``severity``, and ``known_exploited``.

    Raises
    ------
    Exception
        Any database error is re-raised after rolling back the transaction.
    """
    norm_product, norm_version = _key(product, version)
    session = SessionLocal()
    try:
        # Step 1 — purge stale rows for this pair.
        session.query(CachedCVE).filter(
            CachedCVE.product == norm_product,
            CachedCVE.version == norm_version,
        ).delete(synchronize_session=False)

        now: datetime = _utcnow()

        if not cve_list:
            # Negative cache: NVD confirmed no CVEs exist for this pair.
            session.add(
                CachedCVE(
                    product=norm_product,
                    version=norm_version,
                    cve_id=NO_CVE_MARKER,
                    cvss_score=None,
                    severity=None,
                    known_exploited=False,
                    cached_at=now,
                )
            )
        else:
            # Step 2 — insert fresh rows, deduplicating by cve_id.
            seen_ids: set[str] = set()
            for entry in cve_list:
                cve_id: str = entry["cve_id"]
                if cve_id in seen_ids:
                    continue
                seen_ids.add(cve_id)
                session.add(
                    CachedCVE(
                        product=norm_product,
                        version=norm_version,
                        cve_id=cve_id,
                        cvss_score=entry.get("cvss_score"),
                        severity=entry.get("severity"),
                        known_exploited=bool(entry.get("known_exploited", False)),
                        cached_at=now,
                    )
                )

        session.commit()

    except Exception:
        session.rollback()
        raise

    finally:
        session.close()


# ---------------------------------------------------------------------------
# Quick-start entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_cache_db()
    print(f"NVD cache database initialized at {DB_PATH}")
