"""CTI hunt sweep: run the tenant's OWN indicators through threat intel.

Gathers the distinct indicators already sitting in the tenant's data —
public src/dst IPs from normalized events, ip/hash/domain/url entities
from the evidence graph — and checks each against every applicable CTI
provider (cache-first, so repeat sweeps are cheap and the VT free-tier
rate limit only bites on cold indicators). Returns the flagged ones with
their local sighting counts: "this IP your fleet talked to is a known
Tor exit with 93/100 abuse confidence" is a hunt lead, not a lookup.
"""

import asyncio
import ipaddress
import uuid
from dataclasses import dataclass, field

import structlog
from sqlalchemy import func, select

from argus.domain.cti import CTIFinding
from argus.infrastructure.db.models import Entity, NormalizedEvent
from argus.infrastructure.db.session import tenant_session
from argus.services.cti import lookup_cti_tenant

log = structlog.get_logger()

_ENTITY_TYPES = ("ip", "hash", "domain", "url")
_CONCURRENCY = 4  # indicators in flight; per-indicator providers stay sequential


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    # multicast (SSDP/LLMNR/mDNS) is technically "global" to ipaddress but
    # asking threat intel about 239.255.255.250 is pure noise and quota burn
    return ip.is_global and not ip.is_multicast


@dataclass
class HuntHit:
    indicator_type: str
    value: str
    local_events: int
    findings: list[CTIFinding] = field(default_factory=list)

    @property
    def max_confidence(self) -> int:
        return max((f.confidence or 0) for f in self.findings)


@dataclass
class HuntResult:
    indicators_checked: int
    hits: list[HuntHit]


async def _collect_indicators(
    tenant_id: uuid.UUID, limit: int
) -> list[tuple[str, str, int]]:
    """Distinct (type, value, local_event_count), busiest first."""
    out: dict[tuple[str, str], int] = {}
    async with tenant_session(tenant_id) as s:
        # public IPs the fleet actually talked to, with sighting volume
        for col in (NormalizedEvent.src_ip, NormalizedEvent.dst_ip):
            rows = (
                await s.execute(
                    select(func.host(col), func.count(NormalizedEvent.id))
                    .where(col.is_not(None))
                    .group_by(col)
                )
            ).all()
            for ip, count in rows:
                if _is_public_ip(ip):
                    key = ("ip", ip)
                    out[key] = out.get(key, 0) + count

        # indicator-shaped entities from the evidence graph
        rows = (
            await s.execute(
                select(Entity.entity_type, Entity.entity_key).where(
                    Entity.entity_type.in_(_ENTITY_TYPES)
                )
            )
        ).all()
        for etype, key_value in rows:
            if etype == "ip" and not _is_public_ip(key_value):
                continue
            key = (etype, key_value.lower() if etype == "hash" else key_value)
            out.setdefault(key, 0)

    ranked = sorted(out.items(), key=lambda kv: kv[1], reverse=True)
    return [(t, v, n) for (t, v), n in ranked[:limit]]


async def hunt_indicators(tenant_id: uuid.UUID, limit: int = 40) -> HuntResult:
    indicators = await _collect_indicators(tenant_id, limit)
    hits: list[HuntHit] = []
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def check(itype: str, value: str, local_events: int) -> None:
        async with sem:
            try:
                findings = await lookup_cti_tenant(tenant_id, itype, value)
            except Exception as exc:  # noqa: BLE001 - one indicator never kills the sweep
                log.warning("cti_hunt_indicator_failed", indicator=value, error=str(exc)[:200])
                return
        flagged = [f for f in findings if f.found]
        if flagged:
            hits.append(HuntHit(itype, value, local_events, flagged))

    await asyncio.gather(*(check(t, v, n) for t, v, n in indicators))

    hits.sort(key=lambda h: (h.max_confidence, h.local_events), reverse=True)
    log.info(
        "cti_hunt_swept",
        tenant_id=str(tenant_id),
        indicators=len(indicators),
        hits=len(hits),
    )
    return HuntResult(indicators_checked=len(indicators), hits=hits)
