"""CISA KEV — Known Exploited Vulnerabilities.

Free JSON feed (no key). Answers: is this CVE known to be actively
exploited in the wild, and since when? The catalog is fetched once and
cached in-process (it's a single ~1MB file, updated daily).
"""

import time
from typing import Any

import httpx

from argus.domain.cti import CTIFinding

_FEED = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_CACHE_TTL = 6 * 3600  # refresh the catalog every 6h


class CISAKevProvider:
    provider = "cisa_kev"
    supported_types = frozenset({"cve"})

    def __init__(self) -> None:
        self._catalog: dict[str, dict[str, Any]] = {}
        self._fetched_at = 0.0

    async def _ensure_catalog(self) -> None:
        if self._catalog and (time.time() - self._fetched_at) < _CACHE_TTL:
            return
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(_FEED, headers={"User-Agent": "argus-cti"})
            resp.raise_for_status()
            data = resp.json()
        self._catalog = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
        self._fetched_at = time.time()

    async def lookup(self, indicator_type: str, value: str) -> CTIFinding:
        await self._ensure_catalog()
        cve = value.upper()
        entry = self._catalog.get(cve)
        if not entry:
            return CTIFinding(provider="cisa_kev", indicator_type="cve",
                             indicator_value=value, found=False)
        return CTIFinding(
            provider="cisa_kev",
            indicator_type="cve",
            indicator_value=value,
            found=True,
            tags=["actively-exploited"],
            first_seen=entry.get("dateAdded"),
            reference_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            summary=(
                f"{cve} is in CISA KEV (actively exploited). "
                f"{entry.get('vulnerabilityName', '')}. "
                f"Added {entry.get('dateAdded')}. "
                f"Action: {entry.get('requiredAction', 'n/a')}"
            ),
            raw={"product": entry.get("product"), "vendor": entry.get("vendorProject")},
        )
