"""Technique mapping: vendor IDs first, deterministic rules as fallback.

Precedence (ADR 0009):
1. VENDOR — if the connector supplied ATT&CK IDs, trust them (conf 100).
2. RULES  — otherwise run the deterministic classifier over normalized
            fields. Each match carries its own confidence.
3. AI     — Phase 3 augments the ambiguous long tail (same table, same
            interface, mapping_source='ai').

Every mapping records mapping_source + confidence, so coverage is
auditable and the AI can later be validated against vendor+rules.
"""

import re
import uuid

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from argus.infrastructure.db.models import EventTechnique, NormalizedEvent
from argus.services.technique_rules import classify

_TID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_vendor_technique_ids(event: NormalizedEvent) -> list[str]:
    attrs = event.attributes or {}
    ids: set[str] = set()
    raw = attrs.get("mitre_technique_ids")
    if isinstance(raw, list):
        ids.update(str(x).upper() for x in raw if _TID_RE.fullmatch(str(x).upper()))
    elif isinstance(raw, str):
        ids.update(_TID_RE.findall(raw.upper()))
    return sorted(ids)


# kept for backwards-compatible imports in existing tests
extract_technique_ids = extract_vendor_technique_ids


async def _link(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    event: NormalizedEvent,
    technique_id: str,
    source: str,
    confidence: int,
) -> None:
    stmt = pg_insert(EventTechnique).values(
        tenant_id=tenant_id,
        normalized_event_id=event.id,
        technique_id=technique_id,
        event_time=event.event_time,
        mapping_source=source,
        confidence=confidence,
    )
    # If a mapping already exists for this (event, technique), keep it —
    # vendor is written first and should not be downgraded by a rule.
    stmt = stmt.on_conflict_do_nothing(constraint="uq_event_technique")
    await session.execute(stmt)


async def map_techniques(
    session: AsyncSession, tenant_id: uuid.UUID, event: NormalizedEvent
) -> int:
    """Map an event to techniques. Vendor IDs win; rules fill the gap."""
    vendor_ids = extract_vendor_technique_ids(event)
    if vendor_ids:
        for tid in vendor_ids:
            await _link(session, tenant_id, event, tid, "vendor", 100)
        return len(vendor_ids)

    matches = classify(event)
    for m in matches:
        await _link(session, tenant_id, event, m.technique_id, "rules", m.confidence)
    return len(matches)


# backwards-compatible name used by ingestion
link_techniques = map_techniques
