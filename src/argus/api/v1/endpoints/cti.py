"""CTI lookup endpoint: real-world threat intel with citations."""

import ipaddress
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from argus.api.deps import CurrentUser, get_current_user
from argus.cti.registry import get_cti_providers
from argus.infrastructure.db.models import Entity, NormalizedEvent
from argus.infrastructure.db.session import tenant_session
from argus.services.cti import lookup_cti_tenant
from argus.services.cti_hunt import hunt_indicators

router = APIRouter(prefix="/cti", tags=["cti"])

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class CTILookupIn(BaseModel):
    indicator_type: str = Field(pattern=r"^(ip|domain|url|hash|cve)$")
    value: str = Field(min_length=1, max_length=512)


class CTIFindingOut(BaseModel):
    provider: str
    found: bool
    malware: list[str]
    threat_actors: list[str]
    tags: list[str]
    first_seen: str | None
    last_seen: str | None
    confidence: int | None
    reference_url: str | None
    summary: str | None
    details: dict[str, Any] = {}
    raw: dict[str, Any] = {}


class SightingsOut(BaseModel):
    """Where this indicator already appears in the tenant's OWN data."""

    events: int
    entity: bool
    first_seen: str | None
    last_seen: str | None


class CTILookupOut(BaseModel):
    indicator_type: str
    value: str
    findings: list[CTIFindingOut]
    providers_queried: int
    any_found: bool
    sightings: SightingsOut | None = None


async def _local_sightings(
    tenant_id, indicator_type: str, value: str
) -> SightingsOut | None:
    """The pivot from intel to hunt: is this indicator in OUR telemetry?"""
    async with tenant_session(tenant_id) as s:
        events = 0
        first = last = None
        if indicator_type == "ip":
            row = (
                await s.execute(
                    select(
                        func.count(NormalizedEvent.id),
                        func.min(NormalizedEvent.event_time),
                        func.max(NormalizedEvent.event_time),
                    ).where(
                        or_(
                            func.host(NormalizedEvent.src_ip) == value,
                            func.host(NormalizedEvent.dst_ip) == value,
                        )
                    )
                )
            ).one()
            events, first, last = row[0] or 0, row[1], row[2]
        entity = await s.scalar(
            select(Entity.id).where(
                Entity.entity_type == indicator_type,
                func.lower(Entity.entity_key) == value.lower(),
            )
        )
    if events == 0 and entity is None:
        return None
    return SightingsOut(
        events=events,
        entity=entity is not None,
        first_seen=first.isoformat() if first else None,
        last_seen=last.isoformat() if last else None,
    )


@router.post("/lookup", response_model=CTILookupOut)
async def cti_lookup(
    body: CTILookupIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CTILookupOut:
    if body.indicator_type == "ip":
        try:
            ipaddress.ip_address(body.value)
        except ValueError:
            raise HTTPException(422, "invalid IP") from None
    if body.indicator_type == "cve" and not _CVE_RE.match(body.value):
        raise HTTPException(422, "invalid CVE id (expected CVE-YYYY-NNNN)") from None

    findings = await lookup_cti_tenant(current.tenant_id, body.indicator_type, body.value)
    applicable = sum(
        1 for p in get_cti_providers() if body.indicator_type in p.supported_types
    )
    out: list[dict[str, Any]] = [
        {
            "provider": f.provider, "found": f.found, "malware": f.malware,
            "threat_actors": f.threat_actors, "tags": f.tags,
            "first_seen": f.first_seen, "last_seen": f.last_seen,
            "confidence": f.confidence, "reference_url": f.reference_url,
            "summary": f.summary, "details": f.details, "raw": f.raw,
        }
        for f in findings
    ]
    return CTILookupOut(
        indicator_type=body.indicator_type,
        value=body.value,
        findings=[CTIFindingOut(**o) for o in out],
        providers_queried=applicable,
        any_found=any(f.found for f in findings),
        sightings=await _local_sightings(
            current.tenant_id, body.indicator_type, body.value
        ),
    )


class HuntHitOut(BaseModel):
    indicator_type: str
    value: str
    local_events: int
    max_confidence: int
    findings: list[CTIFindingOut]


class HuntOut(BaseModel):
    indicators_checked: int
    hits: list[HuntHitOut]


@router.post("/hunt", response_model=HuntOut)
async def cti_hunt(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=200)] = 40,
) -> HuntOut:
    """Sweep the tenant's own indicators (public IPs seen in events,
    ip/hash/domain/url entities) through every CTI provider and return the
    flagged ones — proactive hunting over data already ingested. Cache-first:
    repeat sweeps only spend quota on indicators not seen in 24h."""
    result = await hunt_indicators(current.tenant_id, limit)
    return HuntOut(
        indicators_checked=result.indicators_checked,
        hits=[
            HuntHitOut(
                indicator_type=h.indicator_type,
                value=h.value,
                local_events=h.local_events,
                max_confidence=h.max_confidence,
                findings=[
                    CTIFindingOut(
                        provider=f.provider, found=f.found, malware=f.malware,
                        threat_actors=f.threat_actors, tags=f.tags,
                        first_seen=f.first_seen, last_seen=f.last_seen,
                        confidence=f.confidence, reference_url=f.reference_url,
                        summary=f.summary, details=f.details, raw=f.raw,
                    )
                    for f in h.findings
                ],
            )
            for h in result.hits
        ],
    )
