"""API routes for assets, findings, and summary statistics."""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

try:
    from ..db.database import get_db
    from ..db.models import Asset, Finding
except (ImportError, ValueError):
    from db.database import get_db
    from db.models import Asset, Finding


router = APIRouter()


@router.get("/api/assets", response_model=List[Dict[str, Any]])
def get_assets(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Retrieve a list of all target assets along with finding counts.

    Args:
        db (Session): SQLAlchemy database session.

    Returns:
        List[Dict[str, Any]]: List of asset dictionaries with finding_count.
    """
    assets = db.query(Asset).all()
    return [
        {
            "id": asset.id,
            "hostname": asset.hostname,
            "ip": asset.ip,
            "exposure": asset.exposure,
            "criticality": asset.criticality,
            "finding_count": len(asset.findings),
        }
        for asset in assets
    ]


@router.get("/api/findings", response_model=List[Dict[str, Any]])
def get_findings(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Retrieve a list of all findings sorted by risk score in descending order.

    Args:
        db (Session): SQLAlchemy database session.

    Returns:
        List[Dict[str, Any]]: List of finding dictionaries including associated asset hostname.
    """
    findings = db.query(Finding).order_by(Finding.risk_score.desc().nullslast()).all()
    return [
        {
            "id": finding.id,
            "asset_id": finding.asset_id,
            "asset": finding.asset.hostname if finding.asset else None,
            "port": finding.port,
            "product": finding.product,
            "version": finding.version,
            "cve_id": finding.cve_id,
            "cvss_score": finding.cvss_score,
            "severity": finding.severity,
            "known_exploited": finding.known_exploited,
            "risk_score": finding.risk_score,
            "priority": finding.priority,
            "confidence": finding.confidence,
        }
        for finding in findings
    ]


@router.get("/api/summary", response_model=Dict[str, int])
def get_summary(db: Session = Depends(get_db)) -> Dict[str, int]:
    """Retrieve summary metrics for assets, findings, and priority breakdowns.

    Args:
        db (Session): SQLAlchemy database session.

    Returns:
        Dict[str, int]: Summary dictionary containing total counts and priority breakdown.
    """
    total_assets = db.query(Asset).count()
    findings = db.query(Finding).all()
    total_findings = len(findings)

    critical_count = sum(
        1 for f in findings if f.priority and f.priority.lower() == "critical"
    )
    high_count = sum(
        1 for f in findings if f.priority and f.priority.lower() == "high"
    )
    medium_count = sum(
        1 for f in findings if f.priority and f.priority.lower() == "medium"
    )
    low_count = sum(
        1 for f in findings if f.priority and f.priority.lower() == "low"
    )

    return {
        "total_assets": total_assets,
        "total_findings": total_findings,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
    }
