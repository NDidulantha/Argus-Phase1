"""VirusTotal v3 enricher (ip / domain / hash).

Parsing is a pure function so it is unit-testable without HTTP.
"""

from typing import Any

import httpx

from argus.domain.enrichment import EnrichmentResult

_ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}


def parse_vt_stats(data: dict[str, Any]) -> tuple[int | None, str]:
    stats = (
        data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    )
    if not stats:
        return None, "unknown"
    malicious = int(stats.get("malicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    score = round(malicious / total * 100)
    if malicious >= 5:
        return score, "malicious"
    if malicious >= 1:
        return score, "suspicious"
    return score, "clean"


class VirusTotalEnricher:
    provider = "virustotal"
    supported_types = frozenset(_ENDPOINTS)

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def enrich(self, indicator_type: str, value: str) -> EnrichmentResult:
        url = f"https://www.virustotal.com/api/v3/{_ENDPOINTS[indicator_type]}/{value}"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers={"x-apikey": self._api_key})
            resp.raise_for_status()
            data = resp.json()
        score, verdict = parse_vt_stats(data)
        return EnrichmentResult(
            provider=self.provider,
            indicator_type=indicator_type,
            indicator_value=value,
            score=score,
            verdict=verdict,
            raw=data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
        )
