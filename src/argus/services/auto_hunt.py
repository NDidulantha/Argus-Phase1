"""Autonomous hunter: a timer-driven CTI sweep across every active tenant.

The rest of the platform is reactive — correlation fires after ingest, the
CTI hunt is a button an analyst clicks. But threat intelligence changes even
when a tenant's events don't: an IP the fleet talked to yesterday can be
freshly flagged by VirusTotal / AbuseIPDB today. This loop is the "always
hunting" piece — it wakes on an interval, runs each tenant's own indicators
through threat intel (cti_hunt.hunt_indicators, cache-first) and persists the
hits (cti_hunt.persist_hits) so leads surface in the UI while nobody watches.

Lifecycle: start()/stop() are driven by the app lifespan (main.py). One task
runs the loop; a stop Event lets shutdown interrupt a long sleep promptly.
Every failure is logged and swallowed — the hunter must never crash the app,
and one bad tenant must never abort the sweep.
"""

import asyncio
import contextlib

import structlog
from sqlalchemy import select

from argus.core.config import get_settings
from argus.infrastructure.db.models import Tenant
from argus.infrastructure.db.session import admin_session
from argus.services.cti_hunt import hunt_indicators, persist_hits

log = structlog.get_logger()

_task: asyncio.Task | None = None
_stop = asyncio.Event()


async def _active_tenant_ids() -> list:
    async with admin_session() as s:
        rows = (
            await s.execute(select(Tenant.id).where(Tenant.is_active.is_(True)))
        ).all()
    return [r[0] for r in rows]


async def sweep_once() -> int:
    """Run one full sweep across all active tenants. Returns hits persisted.

    Public so it can be exercised directly in tests without the loop timing.
    """
    settings = get_settings()
    tenants = await _active_tenant_ids()
    total_hits = 0
    for i, tenant_id in enumerate(tenants):
        if _stop.is_set():
            break
        try:
            result = await hunt_indicators(tenant_id, settings.auto_hunt_limit)
            if result.hits:
                total_hits += await persist_hits(tenant_id, result.hits)
        except Exception:  # noqa: BLE001 - one tenant never aborts the sweep
            log.exception("auto_hunt_tenant_failed", tenant_id=str(tenant_id))
        # stagger tenants so a big fleet doesn't hammer CTI providers at once
        if i < len(tenants) - 1 and settings.auto_hunt_stagger_seconds > 0:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    _stop.wait(), timeout=settings.auto_hunt_stagger_seconds
                )
    log.info("auto_hunt_sweep_done", tenants=len(tenants), hits=total_hits)
    return total_hits


async def _loop() -> None:
    settings = get_settings()
    # let the app settle (DB pool, migrations) before the first sweep
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(
            _stop.wait(), timeout=settings.auto_hunt_startup_delay_seconds
        )
    while not _stop.is_set():
        try:
            await sweep_once()
        except Exception:  # noqa: BLE001 - loop must survive any sweep failure
            log.exception("auto_hunt_sweep_failed")
        # sleep the interval, but wake immediately on shutdown
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                _stop.wait(), timeout=settings.auto_hunt_interval_seconds
            )


def start() -> None:
    """Start the background hunt loop (idempotent, config-gated)."""
    global _task
    settings = get_settings()
    if not settings.auto_hunt_enabled:
        return
    if _task is not None and not _task.done():
        return
    _stop.clear()
    _task = asyncio.get_running_loop().create_task(_loop())
    log.info(
        "auto_hunt_started",
        interval_seconds=settings.auto_hunt_interval_seconds,
        limit=settings.auto_hunt_limit,
    )


async def stop() -> None:
    """Signal the loop to stop and await it (graceful shutdown)."""
    global _task
    _stop.set()
    if _task is not None:
        with contextlib.suppress(asyncio.CancelledError):
            await _task
        _task = None
