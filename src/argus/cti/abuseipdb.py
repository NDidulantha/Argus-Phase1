"""AbuseIPDB as a CTI provider — community abuse reports for IPs.

Distinct from the AbuseIPDB enricher (score/verdict): this surfaces the
reporting picture as cited facts. `found` means the community has actually
reported it in the window; a clean IP still answers truthfully.

API: GET https://api.abuseipdb.com/api/v2/check (Key header, free tier).
"""

from typing import Any

import httpx

from argus.domain.cti import CTIFinding


def parse_abuseipdb_intel(value: str, data: dict[str, Any]) -> CTIFinding:
    payload = data.get("data") or {}
    if "abuseConfidenceScore" not in payload:
        return CTIFinding(provider="abuseipdb", indicator_type="ip",
                          indicator_value=value, found=False,
                          summary="No AbuseIPDB record.")
    score = int(payload["abuseConfidenceScore"])
    reports = int(payload.get("totalReports") or 0)

    tags = []
    if payload.get("usageType"):
        tags.append(payload["usageType"])
    if payload.get("isTor"):
        tags.append("tor-exit")
    if payload.get("countryCode"):
        tags.append(payload["countryCode"])

    origin = ", ".join(x for x in (payload.get("isp"), payload.get("countryCode")) if x)
    summary = (
        f"Abuse confidence {score}/100 — {reports} report(s) in the last 90 days"
        + (f" ({origin})." if origin else ".")
    )
    return CTIFinding(
        provider="abuseipdb",
        indicator_type="ip",
        indicator_value=value,
        found=reports > 0,
        tags=tags,
        last_seen=(payload.get("lastReportedAt") or "")[:10] or None,
        confidence=score,
        reference_url=f"https://www.abuseipdb.com/check/{value}",
        summary=summary,
        raw={"abuseConfidenceScore": score, "totalReports": reports},
    )


class AbuseIPDBIntelProvider:
    provider = "abuseipdb"
    supported_types = frozenset({"ip"})

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        return parse_abuseipdb_intel(value, data)
