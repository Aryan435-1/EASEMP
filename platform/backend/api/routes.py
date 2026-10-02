"""API routes for assets, findings, summary statistics, and security assessment report."""

from datetime import datetime
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
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


@router.get("/api/report", response_class=HTMLResponse)
def get_report(db: Session = Depends(get_db)) -> HTMLResponse:
    """Generate a self-contained, printable HTML security assessment report.

    Queries all assets and findings from the database, renders an HTML document with
    executive summary, asset inventory, and risk-ranked findings tables, formatted
    with dark-mode styling matching the EEIP dashboard. Users can use the browser's
    Print to PDF feature to save the document.

    Args:
        db (Session): SQLAlchemy database session.

    Returns:
        HTMLResponse: Self-contained HTML report string.
    """
    assets = db.query(Asset).all()
    findings = db.query(Finding).order_by(Finding.risk_score.desc().nullslast()).all()

    total_assets = len(assets)
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

    generated_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Build Asset Rows
    asset_rows_html = ""
    for asset in assets:
        finding_count = len(asset.findings)
        asset_rows_html += f"""
        <tr>
            <td>{asset.hostname or 'N/A'}</td>
            <td>{asset.ip or 'N/A'}</td>
            <td>{asset.exposure or 'N/A'}</td>
            <td>{asset.criticality if asset.criticality is not None else 'N/A'}</td>
            <td>{finding_count}</td>
        </tr>
        """

    # Helper for priority colors
    def get_priority_color(priority_str: str) -> str:
        p = (priority_str or "").lower()
        if p == "critical":
            return "#ef4444"
        elif p == "high":
            return "#f97316"
        elif p == "medium":
            return "#eab308"
        elif p == "low":
            return "#22c55e"
        return "#9ca3af"

    # Build Finding Rows
    finding_rows_html = ""
    for f in findings:
        asset_name = f.asset.hostname if f.asset else "N/A"
        product_ver = f"{f.product or ''} {f.version or ''}".strip() or "N/A"
        p_color = get_priority_color(f.priority)
        finding_rows_html += f"""
        <tr>
            <td>{asset_name}</td>
            <td>{f.port if f.port is not None else 'N/A'}</td>
            <td>{product_ver}</td>
            <td>{f.cve_id or 'N/A'}</td>
            <td>{f.risk_score if f.risk_score is not None else 'N/A'}</td>
            <td style="color: {p_color}; font-weight: bold;">{f.priority or 'N/A'}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EEIP Security Assessment Report</title>
    <style>
        body {{
            background-color: #0f172a;
            color: #f8fafc;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0;
            padding: 40px 20px;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            background-color: #0f172a;
        }}
        h1 {{
            color: #f8fafc;
            font-size: 1.75rem;
            margin-top: 0;
            margin-bottom: 8px;
            border-bottom: 2px solid #334155;
            padding-bottom: 16px;
        }}
        .timestamp {{
            color: #94a3b8;
            font-size: 0.9rem;
            margin-bottom: 28px;
        }}
        .section {{
            margin-bottom: 32px;
        }}
        h2 {{
            color: #cbd5e1;
            font-size: 1.3rem;
            margin-bottom: 12px;
        }}
        .summary-box {{
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            line-height: 1.6;
        }}
        .summary-line {{
            font-size: 1.05rem;
            color: #e2e8f0;
            margin: 0;
        }}
        .badge {{
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .badge-critical {{ color: #ef4444; }}
        .badge-high {{ color: #f97316; }}
        .badge-medium {{ color: #eab308; }}
        .badge-low {{ color: #22c55e; }}

        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: #1e293b;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #334155;
            margin-top: 8px;
        }}
        th {{
            background-color: #0f172a;
            color: #94a3b8;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid #334155;
            color: #e2e8f0;
            font-size: 0.9rem;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .closing-note {{
            margin-top: 40px;
            padding: 16px 20px;
            background-color: #1e293b;
            border-left: 4px solid #38bdf8;
            border-radius: 4px;
            color: #94a3b8;
            font-size: 0.875rem;
            line-height: 1.5;
        }}

        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #000000 !important;
            }}
            .report-container {{
                background-color: #ffffff !important;
            }}
            h1, h2, td, .summary-line {{
                color: #000000 !important;
            }}
            th {{
                background-color: #f1f5f9 !important;
                color: #475569 !important;
            }}
            table, .summary-box, .closing-note {{
                background-color: #ffffff !important;
                border-color: #cbd5e1 !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <h1>Enterprise Attack Surface & Exposure Management Platform — Security Assessment Report</h1>
        <div class="timestamp">Generated timestamp: {generated_timestamp}</div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="summary-box">
                <p class="summary-line">
                    <strong>Total Assets:</strong> {total_assets} &nbsp;|&nbsp; 
                    <strong>Total Findings:</strong> {total_findings} &nbsp;|&nbsp; 
                    <strong>Breakdown:</strong> 
                    <span class="badge badge-critical">Critical: {critical_count}</span>, 
                    <span class="badge badge-high">High: {high_count}</span>, 
                    <span class="badge badge-medium">Medium: {medium_count}</span>, 
                    <span class="badge badge-low">Low: {low_count}</span>
                </p>
            </div>
        </div>

        <div class="section">
            <h2>Asset Inventory</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>IP</th>
                        <th>Exposure</th>
                        <th>Criticality</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {asset_rows_html}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Asset</th>
                        <th>Port</th>
                        <th>Product/Version</th>
                        <th>CVE</th>
                        <th>Risk Score</th>
                        <th>Priority</th>
                    </tr>
                </thead>
                <tbody>
                    {finding_rows_html}
                </tbody>
            </table>
        </div>

        <div class="closing-note">
            This report was generated by the EEIP platform based on automated discovery and risk scoring. Findings should be validated by a security analyst before remediation action.
        </div>
    </div>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
