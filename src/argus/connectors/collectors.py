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


# --- CrowdStrike Falcon (Alerts API v2) ---------------------------------

def build_alert_filter(cursor: str | None, since: str) -> str:
    """Falcon FQL: alerts whose timestamp is strictly after the resume point.

    Same monotonic-cursor contract as Wazuh — `>` never re-pulls the boundary
    alert; `since` (now - lookback) bounds the very first poll.
    """
    return f"timestamp:>'{cursor if cursor else since}'"


def parse_crowdstrike_alerts(body: dict[str, Any]) -> CollectResult:
    """Extract hydrated alert resources and the new cursor (max timestamp)."""
    resources = body.get("resources") or []
    payloads = [r for r in resources if isinstance(r, dict)]
    cursor = None
    for p in payloads:
        ts = p.get("timestamp")
        if ts and (cursor is None or ts > cursor):
            cursor = ts
    return CollectResult(payloads=payloads, cursor=cursor, detail=f"pulled {len(payloads)} alerts")


class CrowdStrikeCollector:
    vendor = "crowdstrike"
    source = "crowdstrike"

    def __init__(self, credentials: dict[str, Any], *, timeout: float = 20.0):
        self._id = credentials.get("client_id", "")
        self._secret = credentials.get("client_secret", "")
        self._timeout = timeout

    async def _authenticate(self, client: httpx.AsyncClient, base: str) -> str:
        resp = await client.post(
            f"{base}/oauth2/token",
            data={"client_id": self._id, "client_secret": self._secret},
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    async def collect(
        self, connector: Connector, cursor: str | None, since: str, *, limit: int
    ) -> CollectResult:
        base = connector.endpoint_url.rstrip("/")
        flt = build_alert_filter(cursor, since)
        async with httpx.AsyncClient(verify=connector.verify_tls, timeout=self._timeout) as client:
            headers = {"Authorization": f"Bearer {await self._authenticate(client, base)}"}
            # 1) query the composite IDs of new alerts, oldest first
            q = await client.get(
                f"{base}/alerts/queries/alerts/v2",
                headers=headers,
                params={"filter": flt, "sort": "timestamp|asc", "limit": limit},
            )
            q.raise_for_status()
            ids = q.json().get("resources") or []
            if not ids:
                return CollectResult(payloads=[], cursor=None, detail="no new alerts")
            # 2) hydrate them into full alert resources
            h = await client.post(
                f"{base}/alerts/entities/alerts/v2", headers=headers, json={"composite_ids": ids}
            )
            h.raise_for_status()
        return parse_crowdstrike_alerts(h.json())


# vendor -> factory(credentials) -> Collector. A vendor is pollable only if it
# appears here AND has a normalizer registered for its `source`.
_COLLECTORS: dict[str, Any] = {
    WazuhCollector.vendor: WazuhCollector,
    CrowdStrikeCollector.vendor: CrowdStrikeCollector,
}


def get_collector(vendor: str, credentials: dict[str, Any]) -> Collector | None:
    factory = _COLLECTORS.get(vendor)
    return factory(credentials) if factory else None


def is_pollable(vendor: str) -> bool:
    return vendor in _COLLECTORS
