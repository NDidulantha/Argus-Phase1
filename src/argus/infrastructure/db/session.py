"""Async database engine management.

The engine is created lazily and held as a module-level singleton so the
whole app shares one connection pool. pool_pre_ping transparently replaces
dead connections (e.g. after a Postgres restart) instead of surfacing them
as request errors.
"""

import asyncio

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from argus.core.config import get_settings

log = structlog.get_logger()

_engine: AsyncEngine | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    return _engine


async def dispose_engine() -> None:
    global _engine
    if _engine is not None:
        await _engine.dispose()
        _engine = None


async def check_database() -> bool:
    """Cheap connectivity probe used by the readiness endpoint."""
    try:
        async with asyncio.timeout(get_settings().db_ready_timeout_seconds):
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:  # noqa: BLE001 - readiness must never raise
        log.warning("database_unreachable", error=str(exc))
        return False
