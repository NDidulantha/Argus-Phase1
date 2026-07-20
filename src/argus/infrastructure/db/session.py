"""Async database engine and tenant-scoped session management.

RLS contract: tenant-owned tables only return/accept rows where
tenant_id = current_setting('app.current_tenant'). If the setting is not
set, policies evaluate to NULL -> DEFAULT DENY (no rows visible).

tenant_session() opens ONE transaction and sets app.current_tenant with
set_config(..., is_local := true), i.e. transaction-scoped. This is what
makes RLS safe with a shared connection pool: the setting can never leak
onto a pooled connection reused by another tenant's request.
"""

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from argus.core.config import get_settings

log = structlog.get_logger()

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = create_async_engine(get_settings().database_url, pool_pre_ping=True)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_factory


async def dispose_engine() -> None:
    global _engine, _session_factory
    # Clear the module state FIRST, then dispose. If dispose() raises (e.g. a
    # background task still held a connection as the event loop tore down), the
    # next caller must still get a fresh engine — leaving a half-disposed
    # engine bound to a dead loop here would poison every subsequent request.
    engine, _engine, _session_factory = _engine, None, None
    if engine is not None:
        await engine.dispose()


@asynccontextmanager
async def tenant_session(tenant_id: uuid.UUID) -> AsyncIterator[AsyncSession]:
    """A session bound to one tenant for the duration of one transaction.

    All ORM work inside the block runs under RLS for `tenant_id` and is
    committed atomically on exit (rolled back on exception).
    """
    async with get_session_factory()() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.current_tenant', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            yield session


@asynccontextmanager
async def admin_session() -> AsyncIterator[AsyncSession]:
    """Control-plane session with NO tenant context.

    Under default-deny RLS this session sees zero rows in tenant tables;
    it exists for operating on control-plane tables such as `tenants`.
    """
    async with get_session_factory()() as session:
        async with session.begin():
            yield session


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
