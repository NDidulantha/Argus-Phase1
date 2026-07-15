"""Correlation + scoring: turn scattered events into scored evidence.

Deterministic (ADR 0010): correlation groups a tenant's technique-bearing
events by host into time-bounded clusters, gathers the distinct
techniques / tactics / entities involved, and computes an EXPLAINABLE
score. No LLM here — the evidence object is the trustworthy input the
reasoning agent will later consume.

Correlation runs debounced after ingest (services/auto_correlation.py) and
on demand (POST /evidence/correlate) rather than per event: clustering
needs a batch of events to be meaningful, and rerunning is cheap and
idempotent (open objects are replaced; triaged ones are left alone and
their clusters are not resurrected).

Scoring model (fully transparent, see score_breakdown on each object):
  base            = max technique confidence contribution
  tactic_breadth  = +8 per distinct ATT&CK tactic (attack progresses)
  technique_count = +4 per distinct technique (capped)
  critical_bonus  = +20 if a high-severity technique is present
                    (credential access, privilege escalation, lateral mvmt)
  volume          = +min(10, events/20)
Score is clamped to 0..100. Every term is recorded so an analyst can see
exactly why an object scored as it did.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.infrastructure.db.models import (
    EntityEdge,
    EventTechnique,
    EvidenceObject,
    MitreTechnique,
    NormalizedEvent,
)

# tactics that signal a real intrusion in progress -> critical bonus
_CRITICAL_TACTICS = {
    "credential-access",
    "privilege-escalation",
    "lateral-movement",
    "exfiltration",
    "command-and-control",
}


@dataclass
class _Cluster:
    host: str | None
    events: list


def _score(techniques, tactics, event_count, max_conf) -> tuple[int, dict]:
    base = round(max_conf * 0.4)
    tactic_breadth = 8 * len(tactics)
    technique_count = min(4 * len(techniques), 20)
    critical_bonus = 20 if (_CRITICAL_TACTICS & set(tactics)) else 0
    volume = min(10, event_count // 20)
    total = base + tactic_breadth + technique_count + critical_bonus + volume
    total = max(0, min(100, total))
    breakdown = {
        "base_from_confidence": base,
        "tactic_breadth": tactic_breadth,
        "technique_count": technique_count,
        "critical_tactic_bonus": critical_bonus,
        "volume": volume,
        "total": total,
    }
    return total, breakdown


async def correlate_tenant(
    session: AsyncSession, tenant_id: uuid.UUID, window_minutes: int = 30
) -> int:
    """(Re)build open evidence objects for a tenant. Returns objects written."""
    # Pull technique-bearing events joined to their techniques, ordered by
    # host then time so we can walk them into per-host time windows.
    rows = (
        await session.execute(
            select(
                NormalizedEvent.id,
                NormalizedEvent.host_name,
                NormalizedEvent.event_time,
                EventTechnique.technique_id,
                EventTechnique.confidence,
            )
            .join(EventTechnique, EventTechnique.normalized_event_id == NormalizedEvent.id)
            .order_by(NormalizedEvent.host_name, NormalizedEvent.event_time)
        )
    ).all()
    if not rows:
        return 0

    # technique_id -> tactics, for breadth scoring
    tech_ids = {r.technique_id for r in rows}
    tactic_map: dict[str, list[str]] = {}
    if tech_ids:
        techs = (
            await session.scalars(
                select(MitreTechnique).where(MitreTechnique.technique_id.in_(tech_ids))
            )
        ).all()
        tactic_map = {t.technique_id: (t.tactics or []) for t in techs}

    # group into per-host, time-bounded clusters
    window = timedelta(minutes=window_minutes)
    clusters: list[dict] = []
    cur: dict | None = None
    for r in rows:
        if (
            cur is None
            or r.host_name != cur["host"]
            or r.event_time - cur["last_time"] > window
        ):
            cur = {
                "host": r.host_name,
                "start": r.event_time,
                "last_time": r.event_time,
                "event_ids": set(),
                "techs": {},
            }
            clusters.append(cur)
        cur["last_time"] = r.event_time
        cur["event_ids"].add(r.id)
        cur["techs"][r.technique_id] = max(cur["techs"].get(r.technique_id, 0), r.confidence)

    # replace existing OPEN objects for this tenant (idempotent rerun)
    await session.execute(
        delete(EvidenceObject).where(EvidenceObject.status == "open")
    )

    # Triaged (non-open) objects survive the rerun — and their clusters must
    # not come back as fresh open alerts, or dismissing would be pointless.
    triaged = (
        await session.execute(
            select(
                EvidenceObject.host_name,
                EvidenceObject.window_start,
                EvidenceObject.window_end,
            ).where(EvidenceObject.status != "open")
        )
    ).all()

    def _already_triaged(host, start, end) -> bool:
        return any(
            t.host_name == host and start <= t.window_end and end >= t.window_start
            for t in triaged
        )

    written = 0
    for c in clusters:
        if _already_triaged(c["host"], c["start"], c["last_time"]):
            continue
        techniques = sorted(c["techs"])
        tactics = sorted({t for tid in techniques for t in tactic_map.get(tid, [])})
        max_conf = max(c["techs"].values()) if c["techs"] else 0
        event_count = len(c["event_ids"])
        score, breakdown = _score(techniques, tactics, event_count, max_conf)

        # entities seen on this host in the window (via edges touching it)
        entity_ids: list[int] = []
        if c["host"]:
            edge_rows = (
                await session.execute(
                    select(EntityEdge.src_entity_id, EntityEdge.dst_entity_id).where(
                        EntityEdge.last_seen >= c["start"],
                        EntityEdge.first_seen <= c["last_time"],
                    )
                )
            ).all()
            ids: set[int] = set()
            for er in edge_rows:
                ids.add(er.src_entity_id)
                ids.add(er.dst_entity_id)
            entity_ids = sorted(ids)[:200]

        session.add(
            EvidenceObject(
                tenant_id=tenant_id,
                host_name=c["host"],
                window_start=c["start"],
                window_end=c["last_time"],
                event_count=event_count,
                technique_ids=techniques,
                tactics=tactics,
                entity_ids=entity_ids,
                score=score,
                score_breakdown=breakdown,
                status="open",
            )
        )
        written += 1

    return written
