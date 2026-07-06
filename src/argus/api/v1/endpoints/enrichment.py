"""On-demand indicator enrichment.

Deliberately NOT inline in ingestion: enriching at event rates would burn
provider quotas and add latency to the hot path. Analysts (and later the
hunting agents) enrich the indicators an investigation actually touches.
"""

import ipaddress
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from argus.api.deps import CurrentUser, get_current_user
from argus.enrichers.registry import get_enrichers
from argus.infrastructure.db.session import tenant_session
from argus.services.enrichment import lookup_indicator

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


class LookupIn(BaseModel):
    indicator_type: str = Field(pattern=r"^(ip|domain|hash)$")
    value: str = Field(min_length=1, max_length=512)


class LookupEntryOut(BaseModel):
    provider: str
    score: int | None
    verdict: str
    cached: bool
    fetched_at: datetime


class LookupOut(BaseModel):
    indicator_type: str
    value: str
    results: list[LookupEntryOut]
    providers_enabled: int


@router.post("/lookup", response_model=LookupOut)
async def lookup(
    body: LookupIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> LookupOut:
    if body.indicator_type == "ip":
        try:
            ipaddress.ip_address(body.value)
        except ValueError:
            raise HTTPException(422, "not a valid IP address") from None

    async with tenant_session(current.tenant_id) as session:
        entries = await lookup_indicator(session, body.indicator_type, body.value)

    return LookupOut(
        indicator_type=body.indicator_type,
        value=body.value,
        results=[LookupEntryOut(**vars(e)) for e in entries],
        providers_enabled=len(get_enrichers()),
    )
