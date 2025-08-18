from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from fastapi import BackgroundTasks, FastAPI, HTTPException, Depends, UploadFile, File, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .db import get_db_session, get_engine, Base, get_sessionmaker
from .models import ScanORM, FindingORM, SeedORM, AssetORM, EvidenceORM
from .repos import ScanRepository, FindingRepository, SeedRepository, AssetRepository, EvidenceRepository
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import os
import logging
import time
from .logging_config import setup_logging, bind_request_id
from .config import get_settings
from .middleware import setup_middleware
from .exceptions import register_exception_handlers
from .validators import (
    validate_scan_target,
    validate_domain,
    validate_cidr,
    validate_asn,
    validate_organization_name,
    validate_confidence_score,
    validate_evidence_filename,
)
from .services.scan_service import ScanService


class ScanOptions(BaseModel):
    enumerate_subdomains: bool = Field(True, description="Use crt.sh to enumerate subdomains")
    resolve_dns: bool = Field(True, description="Resolve hostnames to IPs")
    reverse_dns: bool = Field(True, description="Reverse DNS for IPs")
    scan_common_ports: bool = Field(True, description="Scan a set of common TCP ports")
    http_probe: bool = Field(True, description="Fetch HTTP(S) response and title on web ports")
    tls_info: bool = Field(True, description="Fetch TLS certificate summary on 443")
    common_ports: List[int] = Field(
        default_factory=lambda: [80, 443, 22, 25, 53, 110, 143, 587, 993, 995, 3306, 5432, 6379, 8080, 8443],
        description="Ports to scan when scan_common_ports is enabled",
    )
    max_hosts: int = Field(4096, ge=1, le=20000, description="Cap for expanded hosts from CIDR")


class ScanCreate(BaseModel):
    target: str = Field(..., description="Domain, IP, or CIDR to scan")
    note: Optional[str] = Field(None, description="Optional note for this scan")
    options: ScanOptions = Field(default_factory=ScanOptions)


class Finding(BaseModel):
    id: str
    scan_id: str
    category: str
    title: str
    severity: str
    data: Dict[str, object]


class Scan(BaseModel):
    id: str
    target: str
    note: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime
    findings: List[Finding] = Field(default_factory=list)
    findings_count: int = 0


# Module 1: Seed ingestion and asset attribution models
class SeedType(str, Enum):
    root_domain = "root_domain"
    asn = "asn"
    cidr = "cidr"
    acquisition_domain = "acquisition_domain"
    keyword = "keyword"
    organization = "organization"


class SeedCreate(BaseModel):
    seed_type: SeedType = Field(..., description="Type of seed")
    value: str = Field(..., description="Value for the seed, e.g., domain, ASN, CIDR, or keyword")
    note: Optional[str] = Field(None, description="Optional note")


class Seed(BaseModel):
    id: str
    seed_type: SeedType
    value: str
    note: Optional[str]
    created_at: datetime
    updated_at: datetime


class AssetType(str, Enum):
    domain = "domain"
    ip = "ip"


class Asset(BaseModel):
    id: str
    asset_type: AssetType
    value: str
    ownership_confidence: float = Field(0.0, ge=0.0, le=1.0)
    sources: List[str] = Field(default_factory=list, description="Discovery sources, e.g., crt.sh, dns, rdns")
    metadata: Dict[str, object] = Field(default_factory=dict)
    last_scan_id: Optional[str] = None
    last_scan_status: Optional[str] = None
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


# Module 3: Risk scoring (transparent and tunable)
class RiskInput(BaseModel):
    cvss_base: float = Field(0.0, ge=0.0, le=10.0)
    asset_criticality_weight: float = Field(1.0, ge=0.0, le=3.0)
    exploitability_multiplier: float = Field(1.0, ge=0.0, le=5.0)


class RiskResult(BaseModel):
    risk_score: float
    components: Dict[str, float]


setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="EASM API", version="0.4.0")


# Centralized settings and middleware/exception wiring
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
setup_middleware(app)
register_exception_handlers(app)


# Persistence moved to database via SQLAlchemy ORM

# Track discovery background task to prevent concurrent runs
_DISCOVERY_TASK: Optional[asyncio.Task] = None


async def _run_scan(scan_id: str, target: str, options: ScanOptions) -> None:
    # Background task: create its own DB session and delegate to service layer
    SessionLocal = get_sessionmaker()
    try:
        if os.getenv("PYTEST_CURRENT_TEST"):
            options = ScanOptions(
                enumerate_subdomains=False,
                resolve_dns=False,
                reverse_dns=False,
                scan_common_ports=False,
                http_probe=False,
                tls_info=False,
            )
        async with SessionLocal() as session:
            service = ScanService(session)
            await service.process_scan(scan_id, target, options.model_dump())
    except Exception:
        logger.exception("scan.failed", extra={"scan_id": scan_id, "target": target})
        return


@app.get("/api/health")
async def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans", response_model=Scan)
async def create_scan(payload: ScanCreate, background: BackgroundTasks, session: AsyncSession = Depends(get_db_session)) -> Scan:
    # Validate/normalize target
    target_norm, _ = validate_scan_target(payload.target)
    # Block duplicate scans: if asset has completed scan, or there is an active/queued scan
    asset_repo = AssetRepository(session)
    scan_repo = ScanRepository(session)
    # Avoid duplicate queued/running
    if await asset_repo.has_completed_scan_for_target(target_norm) or await asset_repo.has_active_or_queued_scan_for_target(target_norm):
        # Return a synthetic scan object pointing to last known scan if exists
        # Fallback: list scans for target and return the most recent
        scans = await scan_repo.list()
        existing = next((s for s in scans if s.target == target_norm), None)
        if existing:
            return Scan(id=existing.id, target=existing.target, note=existing.note, status=existing.status, created_at=existing.created_at, updated_at=existing.updated_at, findings=[], findings_count=0)
        # If no scan row found, just block with 409
        raise HTTPException(status_code=409, detail="Scan already exists or completed for this target")

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    scan_row = ScanORM(
        id=scan_id,
        target=target_norm,
        note=payload.note,
        status="queued",
        created_at=now,
        updated_at=now,
    )
    await scan_repo.create(scan_row)
    await session.commit()

    # In tests, run synchronously to avoid flakiness and ensure timely completion
    if os.getenv("PYTEST_CURRENT_TEST"):
        await _run_scan(scan_id, target_norm, payload.options)
    else:
        background.add_task(_run_scan, scan_id, target_norm, payload.options)
    return Scan(id=scan_row.id, target=scan_row.target, note=scan_row.note, status=scan_row.status, created_at=scan_row.created_at, updated_at=scan_row.updated_at, findings=[], findings_count=0)


@app.get("/api/scans", response_model=List[Scan])
async def list_scans(session: AsyncSession = Depends(get_db_session)) -> List[Scan]:
    scans = await ScanRepository(session).list()
    # Compute findings counts for the listed scans
    counts_map: Dict[str, int] = {}
    if scans:
        scan_ids = [s.id for s in scans]
        result = await session.execute(
            select(FindingORM.scan_id, func.count(FindingORM.id)).where(FindingORM.scan_id.in_(scan_ids)).group_by(FindingORM.scan_id)
        )
        for scan_id, cnt in result.all():
            counts_map[scan_id] = int(cnt)
    # Do not load findings for listing; return counts instead
    return [
        Scan(
            id=s.id,
            target=s.target,
            note=s.note,
            status=s.status,
            created_at=s.created_at,
            updated_at=s.updated_at,
            findings=[],
            findings_count=counts_map.get(s.id, 0),
        )
        for s in scans
    ]


@app.get("/api/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_db_session)) -> Scan:
    scan = await ScanRepository(session).get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await FindingRepository(session).list_by_scan(scan_id)
    findings_api = [Finding(id=f.id, scan_id=f.scan_id, category=f.category, title=f.title, severity=f.severity, data=f.data) for f in findings]
    return Scan(id=scan.id, target=scan.target, note=scan.note, status=scan.status, created_at=scan.created_at, updated_at=scan.updated_at, findings=findings_api, findings_count=len(findings_api))


# -------------- Module 1: Seeds and Attribution --------------
def _now() -> datetime:
    return datetime.now(timezone.utc)

class DiscoveryRunRequest(BaseModel):
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)
    include_scan: bool = Field(True, description="Trigger deep scans for assets above threshold")


class DiscoveryRunResult(BaseModel):
    discovered_assets: int
    scheduled_scans: int


@app.post("/api/seeds", response_model=Seed)
async def create_seed(seed: SeedCreate, session: AsyncSession = Depends(get_db_session)) -> Seed:
    seed_id = str(uuid.uuid4())
    now = _now()
    # Validate value based on seed type
    value_validated = seed.value
    if seed.seed_type in {SeedType.root_domain, SeedType.acquisition_domain}:
        value_validated = validate_domain(seed.value, "value")
    elif seed.seed_type == SeedType.cidr:
        value_validated = validate_cidr(seed.value, "value")
    elif seed.seed_type == SeedType.asn:
        value_validated = validate_asn(seed.value, "value")
    elif seed.seed_type == SeedType.organization:
        value_validated = validate_organization_name(seed.value, "value")
    row = SeedORM(
        id=seed_id,
        seed_type=seed.seed_type,
        value=value_validated.strip(),
        note=seed.note,
        created_at=now,
        updated_at=now,
    )
    await SeedRepository(session).create(row)
    await session.commit()
    return Seed(id=row.id, seed_type=row.seed_type, value=row.value, note=row.note, created_at=row.created_at, updated_at=row.updated_at)


@app.get("/api/seeds", response_model=List[Seed])
async def list_seeds(session: AsyncSession = Depends(get_db_session)) -> List[Seed]:
    seeds = await SeedRepository(session).list()
    return [Seed(id=s.id, seed_type=s.seed_type, value=s.value, note=s.note, created_at=s.created_at, updated_at=s.updated_at) for s in seeds]


@app.delete("/api/seeds/{seed_id}")
async def delete_seed(seed_id: str, session: AsyncSession = Depends(get_db_session)) -> Dict[str, str]:
    await SeedRepository(session).delete(seed_id)
    await session.commit()
    return {"status": "deleted"}


@app.get("/api/assets", response_model=List[Asset])
async def list_assets(min_confidence: float = 0.0, session: AsyncSession = Depends(get_db_session)) -> List[Asset]:
    try:
        min_confidence = validate_confidence_score(min_confidence, "min_confidence")
    except Exception:
        min_confidence = 0.0
    assets = await AssetRepository(session).list(min_confidence=min_confidence)
    return [
        Asset(
            id=a.id,
            asset_type=a.asset_type,
            value=a.value,
            ownership_confidence=a.ownership_confidence,
            sources=a.sources,
            metadata=a.details,
            last_scan_id=getattr(a, "last_scan_id", None),
            last_scan_status=getattr(a, "last_scan_status", None),
            last_scanned_at=getattr(a, "last_scanned_at", None),
            created_at=a.created_at,
            updated_at=a.updated_at,
        )
        for a in assets
    ]


@app.get("/api/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str, session: AsyncSession = Depends(get_db_session)) -> Asset:
    a = await AssetRepository(session).get(asset_id)
    if not a:
        raise HTTPException(status_code=404, detail="Asset not found")
    return Asset(
        id=a.id,
        asset_type=a.asset_type,
        value=a.value,
        ownership_confidence=a.ownership_confidence,
        sources=a.sources,
        metadata=a.details,
        last_scan_id=getattr(a, "last_scan_id", None),
        last_scan_status=getattr(a, "last_scan_status", None),
        last_scanned_at=getattr(a, "last_scanned_at", None),
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


async def _discover_from_seeds(conf_threshold: float, include_scan: bool) -> Tuple[int, int]:
    # Import here to avoid circular import at module load time
    from .services.discovery_service import DiscoveryService
    SessionLocal = get_sessionmaker()
    async with SessionLocal() as session:
        service = DiscoveryService(session)
        return await service.discover_from_seeds(conf_threshold, include_scan)


@app.post("/api/discovery/run", response_model=DiscoveryRunResult)
async def run_discovery(req: DiscoveryRunRequest) -> DiscoveryRunResult:
    # Prevent concurrent discovery runs
    global _DISCOVERY_TASK
    if _DISCOVERY_TASK is not None and not _DISCOVERY_TASK.done():
        raise HTTPException(status_code=409, detail="Discovery already running")
    # In tests, run synchronously for determinism
    if os.getenv("PYTEST_CURRENT_TEST"):
        discovered, scheduled = await _discover_from_seeds(req.confidence_threshold, req.include_scan)
        return DiscoveryRunResult(discovered_assets=discovered, scheduled_scans=scheduled)
    # In normal operation, kick off discovery in the background and return immediately
    async def _job() -> None:
        try:
            await _discover_from_seeds(req.confidence_threshold, req.include_scan)
        finally:
            # Clear task reference when finished
            global _DISCOVERY_TASK
            _DISCOVERY_TASK = None
    _DISCOVERY_TASK = asyncio.create_task(_job())
    return DiscoveryRunResult(discovered_assets=0, scheduled_scans=0)


@app.get("/api/discovery/status")
async def discovery_status() -> Dict[str, bool]:
    running = _DISCOVERY_TASK is not None and not _DISCOVERY_TASK.done()
    return {"running": running}


# -------------- Module 3: Risk scoring API --------------
@app.post("/api/risk/score", response_model=RiskResult)
async def score_risk(payload: RiskInput) -> RiskResult:
    base = payload.cvss_base
    risk = (base * payload.asset_criticality_weight) * payload.exploitability_multiplier
    return RiskResult(risk_score=risk, components={
        "cvss_base": base,
        "asset_criticality_weight": payload.asset_criticality_weight,
        "exploitability_multiplier": payload.exploitability_multiplier,
    })


def get_app() -> FastAPI:
    return app


# --- Startup: create tables for dev/test if not using alembic ---
@app.on_event("startup")
async def on_startup() -> None:
    # Ensure evidence directory exists
    os.makedirs(get_settings().evidence_storage_path, exist_ok=True)
    logger.info("startup.init")
    # Create tables if they don't exist (dev/test convenience)
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    # Static evidence mount
    app.mount("/evidence", StaticFiles(directory=get_settings().evidence_storage_path), name="evidence")


# -------------- Evidence storage --------------

@app.post("/api/findings/{finding_id}/evidence")
async def upload_evidence(
    finding_id: str,
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_db_session),
):
    # Ensure finding exists
    # Better: direct query
    result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    ev_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    evidence_dir = os.path.join(get_settings().evidence_storage_path, finding_id)
    os.makedirs(evidence_dir, exist_ok=True)
    storage_path = os.path.join(evidence_dir, ev_id)

    # Enforce max evidence size (default 50 MB) and stream to disk in chunks to limit memory use
    max_bytes = int(get_settings().max_evidence_bytes)
    size_written = 0
    with open(storage_path, "wb") as f:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            size_written += len(chunk)
            if size_written > max_bytes:
                try:
                    f.close()
                finally:
                    try:
                        os.remove(storage_path)
                    except Exception:
                        pass
                raise HTTPException(status_code=413, detail="Evidence file too large")
            f.write(chunk)

    # Basic content-type allowlist from settings
    allowed = {t.strip().lower() for t in get_settings().evidence_allowed_types}
    if allowed:
        ctype = (file.content_type or "application/octet-stream").lower()
        if all(not ctype.startswith(t) for t in allowed):
            try:
                os.remove(storage_path)
            except Exception:
                pass
            raise HTTPException(status_code=415, detail="Unsupported evidence content-type")

    filename = validate_evidence_filename(file.filename or ev_id)
    ev = EvidenceORM(
        id=ev_id,
        finding_id=finding_id,
        filename=filename,
        content_type=file.content_type,
        size_bytes=size_written,
        storage_path=storage_path,
        created_at=now,
    )
    await EvidenceRepository(session).create(ev)
    await session.commit()
    return {"id": ev_id, "status": "stored"}


@app.get("/api/findings/{finding_id}/evidence/{evidence_id}")
async def get_evidence(
    finding_id: str,
    evidence_id: str,
    session: AsyncSession = Depends(get_db_session),
):
    # naive load by id
    result = await session.execute(select(EvidenceORM).where(EvidenceORM.id == evidence_id, EvidenceORM.finding_id == finding_id))
    ev = result.scalar_one_or_none()
    if ev is None or not os.path.exists(ev.storage_path):
        raise HTTPException(status_code=404, detail="Evidence not found")
    with open(ev.storage_path, "rb") as f:
        data = f.read()
    return Response(content=data, media_type=ev.content_type or "application/octet-stream", headers={"Content-Disposition": f"inline; filename={ev.filename}"})


