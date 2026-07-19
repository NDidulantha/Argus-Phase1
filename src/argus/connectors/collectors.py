"""Collectors: pull new events FROM a live vendor source.

Distinct from normalizers (which shape a payload the platform already has).
A collector connects to the configured endpoint, pulls events newer than a
resume cursor, and hands the raw docs back to the runtime — which ingests
them through the normal path (services/connector_runtime.py). The raw docs
are normalized by the matching normalizer (collector.source -> registry), so
a vendor needs both a collector (how to fetch) and a normalizer (how to map).

Query/parse logic is split into pure helpers so it is unit-testable without
a live indexer; collect() is the only part that touches the network.
"""

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

from argus.infrastructure.db.models import Connector


@dataclass
class CollectResult:
    """Outcome of one poll: the raw docs pulled and the advanced cursor."""

    payloads: list[dict[str, Any]] = field(default_factory=list)
    cursor: str | None = None  # new resume token; None => leave cursor unchanged
    detail: str = ""


class Collector(Protocol):
    vendor: str
    source: str  # normalizer source id the pulled payloads are ingested under

    async def collect(
        self, connector: Connector, cursor: str | None, since: str, *, limit: int
    ) -> CollectResult:
        """Pull events newer than `cursor` (or `since` on the first run)."""
        ...


# --- Wazuh Indexer (OpenSearch) -----------------------------------------

_WAZUH_INDEX = "wazuh-alerts-*"


def build_wazuh_query(cursor: str | None, since: str, limit: int) -> dict[str, Any]:
    """OpenSearch body: events strictly after the resume point, oldest first.

    `gt` (strictly greater) means the boundary doc is never re-ingested;
    ascending sort keeps the cursor monotonic so a crash mid-batch resumes
    cleanly. On the first run (no cursor) we bound the pull with `since`
    (now - lookback) so a fresh connector doesn't drag in years of history.
    """
    lower = cursor if cursor else since
    return {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"range": {"@timestamp": {"gt": lower}}},
    }


def parse_wazuh_hits(body: dict[str, Any]) -> CollectResult:
    """Extract the alert docs and the new cursor (max @timestamp seen)."""
    hits = (body.get("hits") or {}).get("hits") or []
    payloads = [h["_source"] for h in hits if isinstance(h.get("_source"), dict)]
    cursor = None
    for p in payloads:
        ts = p.get("@timestamp")
        if ts and (cursor is None or ts > cursor):
            cursor = ts
    return CollectResult(payloads=payloads, cursor=cursor, detail=f"pulled {len(payloads)} alerts")


class WazuhCollector:
    vendor = "wazuh"
    source = "wazuh"

    def __init__(self, credentials: dict[str, Any], *, timeout: float = 15.0):
        self._auth = (credentials.get("username", ""), credentials.get("password", ""))
        self._timeout = timeout

    async def collect(
        self, connector: Connector, cursor: str | None, since: str, *, limit: int
    ) -> CollectResult:
        url = connector.endpoint_url.rstrip("/") + f"/{_WAZUH_INDEX}/_search"
        query = build_wazuh_query(cursor, since, limit)
        async with httpx.AsyncClient(verify=connector.verify_tls, timeout=self._timeout) as client:
            resp = await client.post(url, json=query, auth=self._auth)
        resp.raise_for_status()
        return parse_wazuh_hits(resp.json())


# vendor -> factory(credentials) -> Collector. A vendor is pollable only if it
# appears here AND has a normalizer registered for its `source`.
_COLLECTORS: dict[str, Any] = {
    WazuhCollector.vendor: WazuhCollector,
}


def get_collector(vendor: str, credentials: dict[str, Any]) -> Collector | None:
    factory = _COLLECTORS.get(vendor)
    return factory(credentials) if factory else None


def is_pollable(vendor: str) -> bool:
    return vendor in _COLLECTORS
