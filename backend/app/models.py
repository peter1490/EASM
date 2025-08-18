from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    findings: Mapped[List["FindingORM"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    data: Mapped[Dict[str, Any]] = mapped_column(JSONB())

    scan: Mapped[ScanORM] = relationship(back_populates="findings")


class EvidenceORM(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    filename: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    size_bytes: Mapped[int] = mapped_column("size_bytes")
    storage_path: Mapped[str] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SeedTypeEnum(str):
    root_domain = "root_domain"
    asn = "asn"
    cidr = "cidr"
    acquisition_domain = "acquisition_domain"
    keyword = "keyword"
    organization = "organization"


# Backward-compatible alias expected by services layer
SeedType = SeedTypeEnum


class SeedORM(Base):
    __tablename__ = "seeds"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    seed_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AssetTypeEnum(str):
    domain = "domain"
    ip = "ip"


# Backward-compatible alias expected by services layer
AssetType = AssetTypeEnum

class AssetORM(Base):
    __tablename__ = "assets"
    __table_args__ = (
        # Ensure uniqueness of asset per type/value
        UniqueConstraint("asset_type", "value", name="uq_asset_type_value"),
        # Add composite index for common queries
        Index("ix_assets_type_confidence", "asset_type", "ownership_confidence"),
        # Add index for scan status queries
        Index("ix_assets_scan_status", "last_scan_status", "last_scanned_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    ownership_confidence: Mapped[float] = mapped_column(Float, index=True)
    sources: Mapped[List[str]] = mapped_column(JSONB())
    details: Mapped[Dict[str, Any]] = mapped_column(JSONB())
    # Scan tracking (nullable for assets never scanned)
    last_scan_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True, index=True)
    last_scan_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


