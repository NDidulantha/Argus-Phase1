"""Auto-correlation: rebuild a tenant's evidence objects shortly after ingest.

Correlation needs a batch of events to cluster meaningfully (ADR 0011), so
instead of running per event it is debounced per tenant: every ingest
(re)arms a short timer and one correlation pass fires once the tenant goes
quiet. Reruns are cheap and idempotent — correlate_tenant replaces open
objects and leaves triaged ones alone — so the alert queue stays live
without anyone calling POST /evidence/correlate by hand.
"""

import asyncio
import uuid

import structlog

from argus.core.config import get_settings
from argus.infrastructure.db.session import tenant_session
from argus.services.correlation import correlate_tenant
from argus.services.rag import embed_evidence

log = structlog.get_logger()

_pending: dict[uuid.UUID, asyncio.Task] = {}


async def _correlate_after(tenant_id: uuid.UUID, delay: float) -> None:
    await asyncio.sleep(delay)
    try:
        settings = get_settings()
        async with tenant_session(tenant_id) as s:
            written = await correlate_tenant(
                s, tenant_id, settings.auto_correlate_window_minutes
            )
            await s.flush()
            await embed_evidence(s, tenant_id)
        log.info(
            "auto_correlation_ran",
            tenant_id=str(tenant_id),
            evidence_objects=written,
        )
    except Exception:  # noqa: BLE001 - background task: log, never crash ingest
        log.exception("auto_correlation_failed", tenant_id=str(tenant_id))
    finally:
        if _pending.get(tenant_id) is asyncio.current_task():
            _pending.pop(tenant_id, None)


def schedule_correlation(tenant_id: uuid.UUID) -> None:
    """(Re)arm the tenant's debounce timer. Called after each ingest."""
    settings = get_settings()
    if not settings.auto_correlate_enabled:
        return
    prev = _pending.get(tenant_id)
    if prev is not None and not prev.done():
        prev.cancel()
    _pending[tenant_id] = asyncio.get_running_loop().create_task(
        _correlate_after(tenant_id, settings.auto_correlate_debounce_seconds)
    )


async def flush_pending() -> None:
    """Await all armed timers now (tests / graceful shutdown)."""
    tasks = [t for t in _pending.values() if not t.done()]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
