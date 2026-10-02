"""SQLAlchemy ORM models for Asset and Finding entities."""

from typing import List, Optional
from sqlalchemy import Boolean, Column, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, relationship

from .database import Base


class Asset(Base):
    """SQLAlchemy ORM model representing a target network or system asset.

    Attributes:
        id (int): Primary key, autoincrementing unique identifier.
        hostname (str): Unique hostname of the asset (cannot be null).
        ip (Optional[str]): IP address of the asset.
        exposure (Optional[str]): Network exposure level ("internal" or "external").
        criticality (Optional[int]): Asset criticality score ranging from 0 to 10.
        findings (List[Finding]): One-to-many relationship with Finding records.
    """

    __tablename__ = "assets"

    id: Mapped[int] = Column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = Column(String, unique=True, nullable=False)
    ip: Mapped[Optional[str]] = Column(String, nullable=True)
    exposure: Mapped[Optional[str]] = Column(String, nullable=True)
    criticality: Mapped[Optional[int]] = Column(Integer, nullable=True)

    # Relationships
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Asset(id={self.id}, hostname='{self.hostname}', ip='{self.ip}', "
            f"exposure='{self.exposure}', criticality={self.criticality})>"
        )


class Finding(Base):
    """SQLAlchemy ORM model representing a security finding/vulnerability.

    Attributes:
        id (int): Primary key, autoincrementing unique identifier.
        asset_id (int): Foreign key referencing Asset.id.
        port (Optional[int]): Network port associated with the finding.
        product (Optional[str]): Affected product or service name.
        version (Optional[str]): Version of the affected product.
        cve_id (Optional[str]): Common Vulnerabilities and Exposures (CVE) identifier.
        cvss_score (Optional[float]): CVSS vulnerability severity score.
        severity (Optional[str]): Severity rating (e.g., Low, Medium, High, Critical).
        known_exploited (Optional[bool]): Flag indicating if CVE is known to be exploited in the wild.
        risk_score (Optional[int]): Overall risk score for the finding.
        priority (Optional[str]): Remediation priority classification.
        confidence (Optional[float]): Detection confidence level score.
        asset (Asset): Many-to-one relationship referencing the parent Asset model.
    """

    __tablename__ = "findings"

    id: Mapped[int] = Column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = Column(Integer, ForeignKey("assets.id"), nullable=False)
    port: Mapped[Optional[int]] = Column(Integer, nullable=True)
    product: Mapped[Optional[str]] = Column(String, nullable=True)
    version: Mapped[Optional[str]] = Column(String, nullable=True)
    cve_id: Mapped[Optional[str]] = Column(String, nullable=True)
    cvss_score: Mapped[Optional[float]] = Column(Float, nullable=True)
    severity: Mapped[Optional[str]] = Column(String, nullable=True)
    known_exploited: Mapped[Optional[bool]] = Column(Boolean, nullable=True)
    risk_score: Mapped[Optional[int]] = Column(Integer, nullable=True)
    priority: Mapped[Optional[str]] = Column(String, nullable=True)
    confidence: Mapped[Optional[float]] = Column(Float, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="findings")

    def __repr__(self) -> str:
        return (
            f"<Finding(id={self.id}, asset_id={self.asset_id}, cve_id='{self.cve_id}', "
            f"severity='{self.severity}', cvss_score={self.cvss_score}, "
            f"known_exploited={self.known_exploited})>"
        )

