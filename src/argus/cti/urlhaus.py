"""URLhaus (abuse.ch) — malicious URL / host intel.

API: POST https://urlhaus-api.abuse.ch/v1/  (Auth-Key header, free).
"""

from typing import Any

import httpx

from argus.domain.cti import CTIFinding

_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def parse_urlhaus(value: str, itype: str, data: dict[str, Any]) -> CTIFinding:
    if data.get("query_status") != "ok":
        return CTIFinding(provider="urlhaus", indicator_type=itype,
                          indicator_value=value, found=False)
    urls = data.get("urls") or []
    tags = sorted({t for u in urls for t in (u.get("tags") or [])})
    return CTIFinding(
        provider="urlhaus",
        indicator_type=itype,
        indicator_value=value,
        found=True,
        tags=tags,
        first_seen=data.get("firstseen"),
        reference_url=data.get("urlhaus_reference"),
        summary=f"Host associated with {len(urls)} malicious URL(s).",
        raw={"url_count": len(urls)},
    )


class URLhausProvider:
    provider = "urlhaus"
    supported_types = frozenset({"ip", "domain"})

    def __init__(self, auth_key: str):
        self._auth_key = auth_key

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                _HOST_URL, data={"host": value}, headers={"Auth-Key": self._auth_key}
            )
            resp.raise_for_status()
            data = resp.json()
        return parse_urlhaus(value, indicator_type, data)
