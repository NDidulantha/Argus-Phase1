"""VirusTotal (v3) as a CTI provider — engine verdicts with citations.

Distinct from the VT enricher (score/verdict for event enrichment): this
answers the Threat Intel questions with cited facts. `found` means the
community actually flags it (malicious+suspicious engines > 0); a clean
record still returns a truthful summary, just not a "known indicator".

Beyond the verdict, each lookup carries structured details for the analyst:
country/ASN/network for IPs (plus historical domain resolutions — what has
this IP hosted?), registrar/DNS for domains, file names/type/signature for
hashes, final URL and page title for URLs.

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


def _details_for(itype: str, attrs: dict[str, Any]) -> dict[str, Any]:
    d: dict[str, Any] = {}
    if itype == "ip":
        if attrs.get("country"):
            d["country"] = attrs["country"]
        if attrs.get("as_owner"):
            d["as_owner"] = attrs["as_owner"]
        if attrs.get("asn"):
            d["asn"] = f"AS{attrs['asn']}"
        if attrs.get("network"):
            d["network"] = attrs["network"]
        if attrs.get("regional_internet_registry"):
            d["registry"] = attrs["regional_internet_registry"]
    elif itype == "domain":
        if attrs.get("registrar"):
            d["registrar"] = attrs["registrar"]
        if attrs.get("creation_date"):
            d["registered"] = _iso(attrs["creation_date"])
        records = attrs.get("last_dns_records") or []
        ips = sorted({r["value"] for r in records if r.get("type") == "A" and r.get("value")})
        if ips:
            d["resolves_to"] = ips[:10]
        categories = sorted(set((attrs.get("categories") or {}).values()))
        if categories:
            d["categories"] = categories[:6]
    elif itype == "hash":
        if attrs.get("meaningful_name"):
            d["file_name"] = attrs["meaningful_name"]
        names = [n for n in (attrs.get("names") or []) if n != attrs.get("meaningful_name")]
        if names:
            d["also_known_as"] = names[:5]
        if attrs.get("type_description"):
            d["file_type"] = attrs["type_description"]
        if attrs.get("size"):
            d["size_bytes"] = attrs["size"]
        signature = (attrs.get("signature_info") or {}).get("product")
        if signature:
            d["claims_to_be"] = signature
        if attrs.get("first_seen_itw_date"):
            d["first_seen_in_wild"] = _iso(attrs["first_seen_itw_date"])
    elif itype == "url":
        if attrs.get("last_final_url"):
            d["final_url"] = attrs["last_final_url"]
        if attrs.get("title"):
            d["page_title"] = attrs["title"]
        categories = sorted(set((attrs.get("categories") or {}).values()))
        if categories:
            d["categories"] = categories[:6]
    if isinstance(attrs.get("reputation"), int) and attrs["reputation"] != 0:
        d["community_reputation"] = attrs["reputation"]
    return d


def parse_virustotal(
    value: str,
    itype: str,
    data: dict[str, Any] | None,
    resolutions: list[str] | None = None,
) -> CTIFinding:
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

    details = _details_for(itype, attrs)
    if resolutions:
        # what this IP has hosted — the "seen anywhere else?" pivot
        details["historical_domains"] = resolutions[:10]

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
        details=details,
        raw={"stats": stats},
    )


class VirusTotalProvider:
    provider = "virustotal"
    supported_types = frozenset({"ip", "domain", "url", "hash"})

    def __init__(self, api_key: str):
        self._api_key = api_key

    async def _resolutions(self, client: httpx.AsyncClient, ip: str) -> list[str]:
        """Historical domain resolutions for an IP. Best-effort: a failure
        here must not cost the analyst the main verdict."""
        try:
            resp = await client.get(
                f"{_API}/ip_addresses/{ip}/resolutions",
                params={"limit": 10},
                headers={"x-apikey": self._api_key},
            )
            resp.raise_for_status()
            rows = resp.json().get("data") or []
            return sorted(
                {
                    r["attributes"]["host_name"]
                    for r in rows
                    if r.get("attributes", {}).get("host_name")
                }
            )
        except Exception:  # noqa: BLE001 - enrichment only, verdict stands
            return []

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
            resolutions = (
                await self._resolutions(client, value) if indicator_type == "ip" else None
            )
        return parse_virustotal(value, indicator_type, data, resolutions)
