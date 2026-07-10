"""CTI lookup endpoint: real-world threat intel with citations."""

import ipaddress
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from argus.api.deps import CurrentUser, get_current_user
from argus.cti.registry import get_cti_providers
from argus.services.cti import lookup_cti_tenant

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


class CTILookupOut(BaseModel):
    indicator_type: str
    value: str
    findings: list[CTIFindingOut]
    providers_queried: int
    any_found: bool


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
            "summary": f.summary,
        }
        for f in findings
    ]
    return CTILookupOut(
        indicator_type=body.indicator_type,
        value=body.value,
        findings=[CTIFindingOut(**o) for o in out],
        providers_queried=applicable,
        any_found=any(f.found for f in findings),
    )
