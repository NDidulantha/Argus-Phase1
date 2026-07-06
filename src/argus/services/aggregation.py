"""Event aggregation: collapse repetition into signals.

Signature strategy: when a stable rule key exists (Wazuh rule_id, Windows
event_id) the signature is category+host+rule_key — so 4,000 PowerShell
pipeline events (same event_id, wildly varying command lines) become ONE
aggregate. Only when no rule key exists does the action text participate.

The upsert targets the partial unique index (tenant_id, signature_hash)
WHERE is_open — atomic increment, no read-modify-write race.
"""

import hashlib
import uuid
from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from argus.infrastructure.db.models import EventAggregate, NormalizedEvent


def compute_signature(
    category: str,
    host_name: str | None,
    action: str | None,
    attributes: dict[str, Any],
) -> str:
    rule_key = str(attributes.get("rule_id") or attributes.get("event_id") or "")
    discriminator = rule_key if rule_key else (action or "")[:120]
    basis = "|".join([category or "", host_name or "", discriminator])
    return hashlib.sha256(basis.encode()).hexdigest()


async def record_aggregate(
    session: AsyncSession, tenant_id: uuid.UUID, event: NormalizedEvent
) -> None:
    signature = compute_signature(
        event.category, event.host_name, event.action, event.attributes
    )
    stmt = pg_insert(EventAggregate).values(
        tenant_id=tenant_id,
        signature_hash=signature,
        category=event.category,
        action=event.action,
        host_name=event.host_name,
        severity_max=event.severity,
        count=1,
        first_seen=event.event_time,
        last_seen=event.event_time,
        sample_normalized_event_id=event.id,
        is_open=True,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[EventAggregate.tenant_id, EventAggregate.signature_hash],
        # bare column, not .is_(True): Postgres matches the partial index
        # predicate structurally, and the index was created as WHERE is_open
        index_where=EventAggregate.is_open,
        set_={
            "count": EventAggregate.count + 1,
            "first_seen": func.least(EventAggregate.first_seen, stmt.excluded.first_seen),
            "last_seen": func.greatest(EventAggregate.last_seen, stmt.excluded.last_seen),
            # greatest() with NULL-safe handling: NULL severities stay NULL
            "severity_max": func.nullif(
                func.greatest(
                    func.coalesce(EventAggregate.severity_max, -1),
                    func.coalesce(stmt.excluded.severity_max, -1),
                ),
                -1,
            ),
        },
    )
    await session.execute(stmt)
