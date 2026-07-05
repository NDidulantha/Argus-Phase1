"""Ingestion service: raw-first, normalize-best-effort.

Design rules (ADR 0006):
1. The raw payload is ALWAYS stored — it is forensic evidence and the
   input for re-normalization when connectors improve.
2. Normalization is best-effort: a malformed event or unknown source must
   never fail the batch. SIEMs retry failed webhooks aggressively; a 500
   on one bad event would duplicate the other 999.
"""

import uuid
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from argus.connectors.registry import get_normalizer
from argus.infrastructure.db.models import NormalizedEvent, RawEvent

log = structlog.get_logger()


@dataclass(frozen=True)
class IngestResult:
    received: int
    normalized: int


async def ingest_events(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    source: str,
    payloads: list[dict[str, Any]],
) -> IngestResult:
    normalizer = get_normalizer(source)
    normalized_count = 0

    for payload in payloads:
        raw = RawEvent(tenant_id=tenant_id, source=source, payload=payload)
        session.add(raw)
        await session.flush()  # assigns raw.id for the FK link

        if normalizer is None:
            continue
        try:
            n = normalizer.normalize(payload)
        except Exception:
            log.warning("normalization_failed", source=source, raw_event_id=raw.id)
            continue
        session.add(
            NormalizedEvent(
                tenant_id=tenant_id,
                raw_event_id=raw.id,
                event_time=n.event_time,
                category=n.category,
                action=n.action,
                severity=n.severity,
                host_name=n.host_name,
                user_name=n.user_name,
                src_ip=n.src_ip,
                dst_ip=n.dst_ip,
                attributes=n.attributes,
            )
        )
        normalized_count += 1

    log.info(
        "events_ingested",
        source=source,
        received=len(payloads),
        normalized=normalized_count,
    )
    return IngestResult(received=len(payloads), normalized=normalized_count)
