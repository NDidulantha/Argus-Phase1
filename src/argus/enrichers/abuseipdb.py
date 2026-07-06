"""AbuseIPDB enricher (ip only). Confidence score is already 0-100."""

from typing import Any

import httpx

from argus.domain.enrichment import EnrichmentResult


def parse_abuseipdb(data: dict[str, Any]) -> tuple[int | None, str]:
    payload = data.get("data", {})
    if "abuseConfidenceScore" not in payload:
        return None, "unknown"
    score = int(payload["abuseConfidenceScore"])
    if score >= 75:
        return score, "malicious"
    if score >= 25:
        return score, "suspicious"
    return score, "clean"


class AbuseIPDBEnricher:
    provider = "abuseipdb"
    supported_types = frozenset({"ip"})

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def enrich(self, indicator_type: str, value: str) -> EnrichmentResult:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        score, verdict = parse_abuseipdb(data)
        return EnrichmentResult(
            provider=self.provider,
            indicator_type=indicator_type,
            indicator_value=value,
            score=score,
            verdict=verdict,
            raw={"abuseConfidenceScore": score},
        )
