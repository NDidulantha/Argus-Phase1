"""VirusTotal (v3) as a CTI provider — engine verdicts with citations.

Distinct from the VT enricher (score/verdict for event enrichment): this
answers the Threat Intel questions with cited facts. `found` means the
community actually flags it (malicious+suspicious engines > 0); a clean
record still returns a truthful summary, just not a "known indicator".

API: GET https://www.virustotal.com/api/v3/{ip_addresses|domains|files|urls}/{id}
(x-apikey header). Free tier is 4 req/min — the 24h CTI cache absorbs that.
"""

import base64
from datetime import UTC, datetime
from typing import Any

import httpx

from argus.domain.cti import CTIFinding

_API = "https://www.virustotal.com/api/v3"

_PATHS = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}
_GUI = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}


def _iso(ts: Any) -> str | None:
    if not isinstance(ts, int | float) or ts <= 0:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d")


def parse_virustotal(value: str, itype: str, data: dict[str, Any] | None) -> CTIFinding:
    if not data or "data" not in data:
        return CTIFinding(provider="virustotal", indicator_type=itype,
                          indicator_value=value, found=False,
                          summary="No VirusTotal record.")
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or None

    malware: list[str] = []
    classification = attrs.get("popular_threat_classification") or {}
    if classification.get("suggested_threat_label"):
        malware.append(classification["suggested_threat_label"])

    gui_id = attrs.get("sha256") or data["data"].get("id") or value
    flagged = malicious + suspicious
    summary = (
        f"{flagged}/{total} engines flag this as malicious or suspicious."
        if total
        else "VirusTotal record exists but carries no analysis stats."
    )
    return CTIFinding(
        provider="virustotal",
        indicator_type=itype,
        indicator_value=value,
        found=flagged > 0,
        malware=malware,
        tags=sorted(attrs.get("tags") or [])[:12],
        first_seen=_iso(attrs.get("first_submission_date")),
        last_seen=_iso(attrs.get("last_analysis_date")),
        confidence=round(100 * flagged / total) if total else None,
        reference_url=f"https://www.virustotal.com/gui/{_GUI[itype]}/{gui_id}",
        summary=summary,
        raw={"stats": stats},
    )


class VirusTotalProvider:
    provider = "virustotal"
    supported_types = frozenset({"ip", "domain", "url", "hash"})

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        ident = value
        if indicator_type == "url":
            # v3 addresses URLs by unpadded urlsafe-base64 of the URL itself
            ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{_API}/{_PATHS[indicator_type]}/{ident}",
                headers={"x-apikey": self._api_key},
            )
            if resp.status_code == 404:  # unknown to VT: truthful not-found
                return parse_virustotal(value, indicator_type, None)
            resp.raise_for_status()
            data = resp.json()
        return parse_virustotal(value, indicator_type, data)
