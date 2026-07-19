"""Connector runtime: poll enabled connectors and pull their events.

The missing half of "always on" — the autonomous hunter re-checks indicators
already ingested; this actually FETCHES fresh events from live sources on a
timer, so a SOC sees new telemetry without anyone pushing it. Each cycle it
walks every enabled connector, pulls events newer than that connector's
cursor via its collector, and feeds them through the normal ingest path
(ingest_events + schedule_correlation), advancing the cursor as it goes.

Lifecycle mirrors services/auto_hunt: start()/stop() driven by the app
lifespan, a stop Event so shutdown interrupts a long sleep, config-gated.
poll_connector never raises — a network/auth failure records status=error on
that one connector and the sweep moves on; nothing crashes the app.
"""

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select

from argus.connectors.collectors import get_collector
from argus.core.config import get_settings
from argus.core.crypto import decrypt_credentials
from argus.infrastructure.db.models import Connector, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.services.auto_correlation import schedule_correlation
from argus.services.ingestion import ingest_events

log = structlog.get_logger()

_task: asyncio.Task | None = None
_stop = asyncio.Event()


async def _active_tenant_ids() -> list:
    async with admin_session() as s:
        rows = (
            await s.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))
        ).all()
    return [r[0] for r in rows]


async def _enabled_connector_ids(tenant_id) -> list[int]:
    async with tenant_session(tenant_id) as s:
        rows = (
            await s.execute(
                select(Connector.id).where(Connector.enabled.is_(True))
            )
        ).all()
    return [r[0] for r in rows]


def _initial_since() -> str:
    """Lower bound for a connector's first-ever poll (now - lookback)."""
    settings = get_settings()
    since = datetime.now(UTC) - timedelta(minutes=settings.connector_initial_lookback_minutes)
    return since.isoformat()


async def poll_connector(tenant_id, connector_id: int) -> int:
    """Poll one connector once: fetch, ingest, advance cursor. Never raises.

    Returns the number of events ingested (0 on a no-op or a handled error).
    """
    settings = get_settings()
    # 1) snapshot config (own transaction; released before the network call)
    async with tenant_session(tenant_id) as s:
        c = await s.get(Connector, connector_id)
        if c is None or not c.enabled:
            return 0
        collector = get_collector(c.vendor, decrypt_credentials(c.credentials))
        if collector is None:
            return 0
        snap = (c.vendor, c.cursor)

    vendor, cursor = snap
    now = datetime.now(UTC)
    # 2) fetch OUTSIDE any transaction (network I/O)
    try:
        result = await collector.collect(
            c, cursor, _initial_since(), limit=settings.connector_batch_size
        )
    except Exception as exc:  # noqa: BLE001 - a source failure is that connector's problem
        log.warning("connector_poll_failed", connector_id=connector_id, error=str(exc)[:300])
        await _mark_error(tenant_id, connector_id, str(exc)[:500], now)
        return 0

    # 3) ingest + advance cursor (own transaction)
    ingested = 0
    try:
        async with tenant_session(tenant_id) as s:
            c = await s.get(Connector, connector_id)
            if c is None:
                return 0
            res = await ingest_events(s, tenant_id, collector.source, result.payloads)
            ingested = res.normalized
            if result.cursor:
                c.cursor = result.cursor
            c.status = "healthy"
            c.last_error = None
            c.last_run_at = now
            c.last_ingested = len(result.payloads)
            c.updated_at = now
    except Exception as exc:  # noqa: BLE001 - ingest fault must not abort the sweep
        log.exception("connector_ingest_failed", connector_id=connector_id)
        await _mark_error(tenant_id, connector_id, str(exc)[:500], now)
        return 0

    if result.payloads:
        schedule_correlation(tenant_id)
    log.info(
        "connector_polled",
        connector_id=connector_id,
        vendor=vendor,
        pulled=len(result.payloads),
        ingested=ingested,
    )
    return ingested


async def _mark_error(tenant_id, connector_id: int, detail: str, when: datetime) -> None:
    with contextlib.suppress(Exception):
        async with tenant_session(tenant_id) as s:
            c = await s.get(Connector, connector_id)
            if c is not None:
                c.status = "error"
                c.last_error = detail
                c.last_run_at = when
                c.updated_at = when


async def sweep_once() -> int:
    """Poll every enabled connector across all active tenants. Returns total
    events ingested. Public so tests can drive one cycle without the timer."""
    total = 0
    for tenant_id in await _active_tenant_ids():
        if _stop.is_set():
            break
        for connector_id in await _enabled_connector_ids(tenant_id):
            if _stop.is_set():
                break
            total += await poll_connector(tenant_id, connector_id)
    return total


async def _loop() -> None:
    settings = get_settings()
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(_stop.wait(), timeout=settings.connector_startup_delay_seconds)
    while not _stop.is_set():
        try:
            await sweep_once()
        except Exception:  # noqa: BLE001 - the loop must survive any sweep failure
            log.exception("connector_sweep_failed")
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                _stop.wait(), timeout=settings.connector_poll_interval_seconds
            )


def start() -> None:
    """Start the polling loop (idempotent, config-gated)."""
    global _task
    settings = get_settings()
    if not settings.connector_runtime_enabled:
        return
    if _task is not None and not _task.done():
        return
    _stop.clear()
    _task = asyncio.get_running_loop().create_task(_loop())
    log.info("connector_runtime_started", interval=settings.connector_poll_interval_seconds)


async def stop() -> None:
    """Signal the loop to stop and await it (graceful shutdown)."""
    global _task
    _stop.set()
    if _task is not None:
        with contextlib.suppress(asyncio.CancelledError):
            await _task
        _task = None
