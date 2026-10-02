"""Data ingestion module for populating PostgreSQL from recon and risk engine JSON files.

Bridges the risk engine's JSON output into the platform's PostgreSQL database by
reading sample recon data and scored findings output, mapping assets to findings,
and storing them using SQLAlchemy ORM models.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from .database import Base, SessionLocal, engine
from .models import Asset, Finding

# Asset business criticality ratings (0-10)
ASSET_CRITICALITY: Dict[str, int] = {
    "api.lab.local": 8,
    "db01.lab.local": 9,
    "vpn01.lab.local": 7,
}
DEFAULT_CRITICALITY: int = 5


def ingest_data() -> None:
    """Ingest asset recon data and risk engine findings into PostgreSQL database.

    Creates tables if missing, clears existing records, parses recon and finding JSON files,
    maps hostnames to asset IDs, and commits new Asset and Finding records.
    """
    # 1. Ensure database tables exist
    Base.metadata.create_all(bind=engine)

    # 2. Open a database session
    db = SessionLocal()

    try:
        # 3. Clear existing data (Finding first, then Asset due to foreign key)
        db.query(Finding).delete()
        db.query(Asset).delete()
        db.commit()

        # Determine paths relative to repository root
        current_dir = Path(__file__).resolve().parent
        repo_root = current_dir.parent.parent.parent

        recon_path = repo_root / "shared" / "sample_data" / "sample_recon_output.json"
        findings_path = repo_root / "risk-engine" / "findings_output.json"

        # 4. Read sample recon output JSON
        with open(recon_path, "r", encoding="utf-8") as f:
            recon_data: List[Dict[str, Any]] = json.load(f)

        # 5. Process unique hostnames and create Asset records
        hostname_to_id: Dict[str, int] = {}
        assets_ingested_count = 0

        for item in recon_data:
            asset_info = item.get("asset", {})
            hostname = asset_info.get("hostname")
            if not hostname or hostname in hostname_to_id:
                continue

            ip = asset_info.get("ip")
            exposure = asset_info.get("exposure")
            criticality = ASSET_CRITICALITY.get(hostname, DEFAULT_CRITICALITY)

            asset_obj = Asset(
                hostname=hostname,
                ip=ip,
                exposure=exposure,
                criticality=criticality,
            )
            db.add(asset_obj)
            db.flush()  # Flush to generate asset_obj.id

            hostname_to_id[hostname] = asset_obj.id
            assets_ingested_count += 1

        # 6. Read findings output JSON
        with open(findings_path, "r", encoding="utf-8") as f:
            findings_data: List[Dict[str, Any]] = json.load(f)

        # 7. Create Finding records mapped to corresponding asset_id
        findings_ingested_count = 0

        for entry in findings_data:
            hostname = entry.get("asset")
            if not hostname or hostname not in hostname_to_id:
                print(f"Warning: Asset '{hostname}' not found in asset mapping. Skipping findings.")
                continue

            asset_id = hostname_to_id[hostname]
            port = entry.get("port")
            product = entry.get("product")
            version = entry.get("version")

            findings_list = entry.get("findings", [])
            for finding_dict in findings_list:
                finding_obj = Finding(
                    asset_id=asset_id,
                    port=port,
                    product=product,
                    version=version,
                    cve_id=finding_dict.get("cve_id"),
                    cvss_score=finding_dict.get("cvss_score"),
                    severity=finding_dict.get("severity"),
                    known_exploited=finding_dict.get("known_exploited"),
                    risk_score=finding_dict.get("risk_score"),
                    priority=finding_dict.get("priority"),
                    confidence=finding_dict.get("confidence"),
                )
                db.add(finding_obj)
                findings_ingested_count += 1

        # 8. Commit the session and print summary
        db.commit()
        print(f"Ingested {assets_ingested_count} assets and {findings_ingested_count} findings.")

    except Exception as e:
        db.rollback()
        raise e
    finally:
        # 9. Close session
        db.close()


if __name__ == "__main__":
    ingest_data()
