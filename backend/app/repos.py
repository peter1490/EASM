from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AssetORM, FindingORM, ScanORM, SeedORM, EvidenceORM
from .modules import is_ip
from .search import index_asset, index_finding, index_evidence


class ScanRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scan: ScanORM) -> ScanORM:
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def get(self, scan_id: str) -> Optional[ScanORM]:
        result = await self.session.execute(select(ScanORM).where(ScanORM.id == scan_id))
        return result.scalar_one_or_none()

    async def list(self) -> List[ScanORM]:
        result = await self.session.execute(select(ScanORM).order_by(ScanORM.created_at.desc()))
        return list(result.scalars().all())


class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, finding: FindingORM) -> FindingORM:
        self.session.add(finding)
        await self.session.flush()
        try:
            index_finding({
                "id": finding.id,
                "scan_id": finding.scan_id,
                "category": finding.category,
                "title": finding.title,
                "severity": finding.severity,
                "data": finding.data,
            })
        except Exception:
            pass
        return finding

    async def list_by_scan(self, scan_id: str) -> List[FindingORM]:
        result = await self.session.execute(select(FindingORM).where(FindingORM.scan_id == scan_id))
        return list(result.scalars().all())


class SeedRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, seed: SeedORM) -> SeedORM:
        self.session.add(seed)
        await self.session.flush()
        return seed

    async def list(self) -> List[SeedORM]:
        result = await self.session.execute(select(SeedORM).order_by(SeedORM.created_at.desc()))
        return list(result.scalars().all())

    async def get_by_type_value(self, seed_type: str, value: str) -> Optional[SeedORM]:
        result = await self.session.execute(
            select(SeedORM).where(SeedORM.seed_type == seed_type, SeedORM.value == value)
        )
        return result.scalar_one_or_none()

    async def delete(self, seed_id: str) -> None:
        await self.session.execute(delete(SeedORM).where(SeedORM.id == seed_id))


class AssetRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, asset: AssetORM) -> AssetORM:
        self.session.add(asset)
        await self.session.flush()
        try:
            index_asset({
                "id": asset.id,
                "asset_type": asset.asset_type,
                "value": asset.value,
                "ownership_confidence": asset.ownership_confidence,
                "sources": asset.sources,
                "details": asset.details,
                "created_at": asset.created_at.isoformat(),
                "updated_at": asset.updated_at.isoformat(),
            })
        except Exception:
            pass
        return asset

    async def get_by_type_value(self, asset_type: str, value: str) -> Optional[AssetORM]:
        result = await self.session.execute(
            select(AssetORM).where(AssetORM.asset_type == asset_type, AssetORM.value == value)
        )
        return result.scalar_one_or_none()

    async def create_or_merge(self, candidate: AssetORM) -> Tuple[AssetORM, bool]:
        """Insert a new asset if not existing, else merge into existing.

        Returns (asset_row, created_new).
        Merge policy:
        - ownership_confidence: keep max
        - sources: union, preserve order and uniqueness
        - details: shallow merge, candidate values override existing for same key
        - updated_at: set to candidate.updated_at
        """
        existing = await self.get_by_type_value(candidate.asset_type, candidate.value)
        if existing is None:
            # Insert as-is
            self.session.add(candidate)
            await self.session.flush()
            try:
                index_asset({
                    "id": candidate.id,
                    "asset_type": candidate.asset_type,
                    "value": candidate.value,
                    "ownership_confidence": candidate.ownership_confidence,
                    "sources": candidate.sources,
                    "details": candidate.details,
                    "created_at": candidate.created_at.isoformat(),
                    "updated_at": candidate.updated_at.isoformat(),
                })
            except Exception:
                pass
            return candidate, True
        # Merge into existing
        try:
            existing.ownership_confidence = max(
                float(existing.ownership_confidence or 0.0), float(candidate.ownership_confidence or 0.0)
            )
        except Exception:
            existing.ownership_confidence = candidate.ownership_confidence

        # Merge sources preserving order and uniqueness
        merged_sources: List[str] = []
        for src in list(existing.sources or []) + list(candidate.sources or []):
            s = str(src)
            if s not in merged_sources:
                merged_sources.append(s)
        existing.sources = merged_sources

        # Shallow merge details
        existing.details = {**(existing.details or {}), **(candidate.details or {})}
        existing.updated_at = candidate.updated_at
        await self.session.flush()
        try:
            index_asset({
                "id": existing.id,
                "asset_type": existing.asset_type,
                "value": existing.value,
                "ownership_confidence": existing.ownership_confidence,
                "sources": existing.sources,
                "details": existing.details,
                "created_at": existing.created_at.isoformat(),
                "updated_at": existing.updated_at.isoformat(),
            })
        except Exception:
            pass
        return existing, False

    async def mark_scan_started(self, asset_type: str, value: str, scan_id: str, when: datetime) -> None:
        existing = await self.get_by_type_value(asset_type, value)
        if existing is None:
            return
        existing.last_scan_id = scan_id
        existing.last_scan_status = "running"
        existing.last_scanned_at = when
        existing.updated_at = when
        await self.session.flush()

    async def mark_scan_finished(self, asset_type: str, value: str, scan_id: str, status: str, when: datetime) -> None:
        existing = await self.get_by_type_value(asset_type, value)
        if existing is None:
            return
        # Only update if same scan_id or no tracking yet
        if existing.last_scan_id in {None, scan_id}:
            existing.last_scan_id = scan_id
            existing.last_scan_status = status
            existing.last_scanned_at = when
            existing.updated_at = when
            await self.session.flush()

    async def has_completed_scan_for_target(self, target: str) -> bool:
        asset_type = "ip" if is_ip(target) or "/" in target else "domain"
        asset = await self.get_by_type_value(asset_type, target)
        if asset is None:
            return False
        return (asset.last_scan_status or "") == "completed"

    async def list(self, min_confidence: float = 0.0) -> List[AssetORM]:
        stmt = select(AssetORM).where(AssetORM.ownership_confidence >= min_confidence).order_by(AssetORM.updated_at.desc())
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get(self, asset_id: str) -> Optional[AssetORM]:
        result = await self.session.execute(select(AssetORM).where(AssetORM.id == asset_id))
        return result.scalar_one_or_none()

    async def has_active_or_queued_scan_for_target(self, target: str) -> bool:
        result = await self.session.execute(
            select(ScanORM).where(
                ScanORM.target == target,
                ScanORM.status.in_(["queued", "running"])  # type: ignore[arg-type]
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None


class EvidenceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: EvidenceORM) -> EvidenceORM:
        self.session.add(evidence)
        await self.session.flush()
        try:
            index_evidence({
                "id": evidence.id,
                "finding_id": evidence.finding_id,
                "filename": evidence.filename,
                "content_type": evidence.content_type,
                "size_bytes": evidence.size_bytes,
                "storage_path": evidence.storage_path,
                "created_at": evidence.created_at.isoformat(),
            })
        except Exception:
            pass
        return evidence

    async def list_by_finding(self, finding_id: str) -> List[EvidenceORM]:
        result = await self.session.execute(select(EvidenceORM).where(EvidenceORM.finding_id == finding_id))
        return list(result.scalars().all())


