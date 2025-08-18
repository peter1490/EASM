from __future__ import annotations

import os
import logging
from typing import AsyncGenerator
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase


def _get_database_url() -> str:
    # Prefer explicit DATABASE_URL; fallback to local PostgreSQL for dev/test
    url = os.getenv("DATABASE_URL", "").strip()
    if url:
        # If user provided a postgres URL without async driver, adapt automatically
        if url.startswith("postgresql://"):
            return url.replace("postgresql://", "postgresql+psycopg://", 1)
        return url
    # Default to local Postgres
    return "postgresql+psycopg://easm:easm@localhost:5432/easm"


DATABASE_URL = _get_database_url()


class Base(DeclarativeBase):
    pass


logger = logging.getLogger(__name__)
engine = create_async_engine(DATABASE_URL, echo=False, future=True)
SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
)


def get_engine():
    return engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return SessionLocal


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    # Ensure schema exists on first use (important for tests)
    await ensure_db_schema_initialized()
    async with SessionLocal() as session:
        yield session


_schema_initialized: bool = False
_schema_lock = asyncio.Lock()


async def ensure_db_schema_initialized() -> None:
    global _schema_initialized
    if _schema_initialized:
        return
    async with _schema_lock:
        if _schema_initialized:
            return
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            # Best-effort: add tracking columns to assets if missing (PostgreSQL only)
            try:
                res = await conn.execute(text(
                    """
                    SELECT column_name FROM information_schema.columns
                    WHERE table_name = 'assets'
                    """
                ))
                existing_cols: set[str] = {str(r[0]) for r in res.fetchall()}

                to_add = []
                if "last_scan_id" not in existing_cols:
                    to_add.append("last_scan_id TEXT")
                if "last_scan_status" not in existing_cols:
                    to_add.append("last_scan_status TEXT")
                if "last_scanned_at" not in existing_cols:
                    to_add.append("last_scanned_at TIMESTAMPTZ")
                for col in to_add:
                    await conn.exec_driver_sql(f"ALTER TABLE assets ADD COLUMN {col}")
            except Exception as exc:
                # Non-fatal; schema might already be up-to-date
                logger.debug("db.schema_migration_skipped", extra={"reason": str(exc)})
        _schema_initialized = True


