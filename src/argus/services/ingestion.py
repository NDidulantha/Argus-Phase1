"""Ingestion service: raw-first, normalize-best-effort, fault-isolated.

Design rules (ADR 0006):
1. The raw payload is ALWAYS stored (sanitized only as far as Postgres
   requires) — forensic evidence and re-normalization input.
2. Normalization is best-effort: malformed events or unknown sources must
   never fail the batch.
3. Fault isolation (added after first live Wazuh data): each event is
   written inside its own SAVEPOINT. One hostile payload — NUL characters
   that JSONB rejects, junk in IP fields, wrong types — fails alone;
   the rest of the batch lands. A batch-wide 500 would make the collector
   retry all 500 events forever because of one bad one.
"""

import ipaddress
import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from argus.connectors.registry import get_normalizer
from argus.infrastructure.db.models import NormalizedEvent, RawEvent
from argus.services.aggregation import record_aggregate

log = structlog.get_logger()


@dataclass(frozen=True)
class IngestResult:
    received: int
    normalized: int
    failed: int


def _strip_nul(obj: Any) -> Any:
    """PostgreSQL JSONB cannot store \\u0000; Windows event data loves it."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {_strip_nul(k): _strip_nul(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_strip_nul(x) for x in obj]
    return obj


def _clean_ip(value: str | None) -> str | None:
    """Vendors put '-', 'any', hostnames etc. in IP fields; INET refuses them."""
    if not value:
        return None
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return None


def _clean_severity(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def ingest_events(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    payloads: list[dict[str, Any]],
) -> IngestResult:
    normalizer = get_normalizer(source)
    normalized_count = 0
    failed_count = 0

    for payload in payloads:
        payload = _strip_nul(payload)

        try:
            async with session.begin_nested():  # SAVEPOINT: this event only
                raw = RawEvent(tenant_id=tenant_id, source=source, payload=payload)
                session.add(raw)
                await session.flush()
        except Exception as exc:  # noqa: BLE001 - isolate, count, continue
            failed_count += 1
            log.warning("raw_event_rejected", source=source, error=str(exc)[:200])
            continue

        if normalizer is None:
            continue
        try:
            n = normalizer.normalize(payload)
            async with session.begin_nested():
                normalized_event = NormalizedEvent(
                    tenant_id=tenant_id,
                    raw_event_id=raw.id,
                    event_time=n.event_time,
                    category=n.category,
                    action=n.action,
                    severity=_clean_severity(n.severity),
                    host_name=n.host_name,
                    user_name=n.user_name,
                    src_ip=_clean_ip(n.src_ip),
                    dst_ip=_clean_ip(n.dst_ip),
                    attributes=n.attributes,
                )
                session.add(normalized_event)
                await session.flush()
            normalized_count += 1
            try:
                async with session.begin_nested():
                    await record_aggregate(session, tenant_id, normalized_event)
            except Exception as exc:  # noqa: BLE001 - aggregation must not block ingestion
                log.warning("aggregation_failed", error=str(exc)[:200])
        except Exception as exc:  # noqa: BLE001 - raw is kept; normalization skipped
            log.warning(
                "normalization_failed", source=source, raw_event_id=raw.id, error=str(exc)[:200]
            )

    log.info(
        "events_ingested",
        source=source,
        received=len(payloads),
        normalized=normalized_count,
        failed=failed_count,
    )
    return IngestResult(
        received=len(payloads), normalized=normalized_count, failed=failed_count
    )
