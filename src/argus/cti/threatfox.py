"""ThreatFox (abuse.ch) — IOC intel with malware + actor attribution.

API: POST https://threatfox-api.abuse.ch/api/v1/  (Auth-Key header, free).
Answers: is this IP/domain/hash/url a known IOC? what malware? tags?
first/last seen? Provides a reference URL for citation.
"""

from typing import Any

import httpx

from argus.domain.cti import CTIFinding

_URL = "https://threatfox-api.abuse.ch/api/v1/"


def parse_threatfox(value: str, itype: str, data: dict[str, Any]) -> CTIFinding:
    if data.get("query_status") != "ok" or not data.get("data"):
        return CTIFinding(provider="threatfox", indicator_type=itype,
                          indicator_value=value, found=False)
    rows = data["data"]
    first = rows[0]
    malware = sorted({r.get("malware_printable") for r in rows if r.get("malware_printable")})
    tags = sorted({t for r in rows for t in (r.get("tags") or [])})
    ioc_id = first.get("id")
    return CTIFinding(
        provider="threatfox",
        indicator_type=itype,
        indicator_value=value,
        found=True,
        malware=malware,
        tags=tags,
        first_seen=first.get("first_seen"),
        last_seen=first.get("last_seen"),
        confidence=first.get("confidence_level"),
        reference_url=f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else None,
        summary=f"Known IOC. Malware: {', '.join(malware) or 'n/a'}.",
        raw={"count": len(rows)},
    )


class ThreatFoxProvider:
    provider = "threatfox"
    supported_types = frozenset({"ip", "domain", "url", "hash"})

    def __init__(self, auth_key: str):
        self._auth_key = auth_key

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                _URL,
                json={"query": "search_ioc", "search_term": value},
                headers={"Auth-Key": self._auth_key},
            )
            resp.raise_for_status()
            data = resp.json()
        return parse_threatfox(value, indicator_type, data)
