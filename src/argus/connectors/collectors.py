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

import json
from dataclasses import dataclass, field
from datetime import datetime
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


def _wazuh_search_after(cursor: str | None) -> list | None:
    """A v2 cursor is the JSON-encoded `sort` array of the last hit."""
    if not cursor:
        return None
    try:
        value = json.loads(cursor)
        return value if isinstance(value, list) else None
    except (ValueError, TypeError):
        return None  # legacy plain-timestamp cursor -> handled as a range floor


def build_wazuh_query(cursor: str | None, since: str, limit: int) -> dict[str, Any]:
    """OpenSearch body using search_after for drop-free, duplicate-free paging.

    A pure `@timestamp > cursor` range drops events when two docs share the
    same millisecond at a batch boundary. Instead we sort by [@timestamp, _id]
    and resume with `search_after: [ts, id]` — the _id tiebreaker makes the
    position unambiguous, so identical timestamps page cleanly with no loss and
    no repeats. The first poll (no cursor) has no position yet, so it is bounded
    by a `since` range floor; a legacy plain-timestamp cursor resumes as a floor
    too and upgrades to a composite cursor on the next batch.
    (Sorting on _id follows the OpenSearch search_after docs; a busy production
    index may pair this with a Point-In-Time.)
    """
    query: dict[str, Any] = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}],
    }
    after = _wazuh_search_after(cursor)
    if after is not None:
        query["search_after"] = after
    else:
        query["query"] = {"range": {"@timestamp": {"gte": cursor if cursor else since}}}
    return query


def parse_wazuh_hits(body: dict[str, Any]) -> CollectResult:
    """Extract the alert docs; the new cursor is the last hit's sort values."""
    hits = (body.get("hits") or {}).get("hits") or []
    payloads = [h["_source"] for h in hits if isinstance(h.get("_source"), dict)]
    cursor = None
    if hits:
        sort_values = hits[-1].get("sort")  # [ts, _id] of the greatest hit
        if sort_values:
            cursor = json.dumps(sort_values)
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

def _decode_boundary(cursor: str | None) -> dict | None:
    """A v2 cursor is {"ts": <max timestamp>, "ids": [composite_ids at ts]}."""
    if not cursor:
        return None
    try:
        value = json.loads(cursor)
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError):
        return None  # legacy plain-timestamp cursor


def build_alert_filter(cursor: str | None, since: str) -> str:
    """Falcon FQL for drop-free incremental paging.

    Falcon has no OpenSearch search_after, so we filter `timestamp:>=` the
    boundary and remember the composite_ids already ingested at that exact
    timestamp — the next poll re-sees them (gte) and skips them in the parser.
    A strict `>` instead would drop any alert sharing the boundary millisecond
    that a `limit`-truncated batch didn't reach. First run / legacy cursor use
    `>` on `since` / the plain timestamp.
    """
    boundary = _decode_boundary(cursor)
    if boundary and boundary.get("ts"):
        return f"timestamp:>='{boundary['ts']}'"
    return f"timestamp:>'{cursor if cursor else since}'"


def parse_crowdstrike_alerts(
    body: dict[str, Any], prev_cursor: str | None = None
) -> CollectResult:
    """Hydrated alerts minus the ones already ingested at the prior boundary.

    New cursor = the greatest timestamp seen plus every composite_id at that
    timestamp (accumulated across polls while parked on the same boundary), so
    a later gte re-fetch skips them all — no drops, no duplicates.
    """
    prev = _decode_boundary(prev_cursor) or {}
    seen = set(prev.get("ids") or [])
    prev_ts = prev.get("ts")

    payloads: list[dict[str, Any]] = []
    max_ts: str | None = None
    ids_at_max: list[str] = []
    for r in body.get("resources") or []:
        if not isinstance(r, dict) or r.get("composite_id") in seen:
            continue  # already ingested at the previous boundary timestamp
        payloads.append(r)
        ts, cid = r.get("timestamp"), r.get("composite_id")
        if not ts:
            continue
        if max_ts is None or ts > max_ts:
            max_ts, ids_at_max = ts, [cid]
        elif ts == max_ts:
            ids_at_max.append(cid)

    cursor = None
    if max_ts is not None:
        ids = set(ids_at_max)
        if prev_ts == max_ts:
            ids |= seen  # still on the same boundary -> keep the whole skip set
        cursor = json.dumps({"ts": max_ts, "ids": sorted(i for i in ids if i)})
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
        return parse_crowdstrike_alerts(h.json(), cursor)


# --- Palo Alto Cortex XDR (get_alerts_multi_events) ---------------------

def _iso_to_ms(iso: str) -> int:
    return int(datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp() * 1000)


def build_cortex_filters(cursor: str | None, since: str, limit: int) -> dict[str, Any]:
    """Cortex request_data: alerts at/after the resume point, oldest first.

    Cortex's creation_time is epoch ms and its only operator is gte, so — like
    CrowdStrike — we gte the boundary and let the parser skip the alert_ids
    already ingested at that exact millisecond (the {ts, ids} skip-set). This
    is drop-free even when a limit-truncated batch splits a same-ms cluster,
    which the earlier max+1 idiom could not survive. `since` (ISO, now -
    lookback) bounds the first poll; a legacy plain-int cursor still resumes.
    """
    boundary = _decode_boundary(cursor)
    if boundary and boundary.get("ts") is not None:
        lower = int(boundary["ts"])
    elif cursor:
        lower = int(cursor)  # legacy max+1 cursor
    else:
        lower = _iso_to_ms(since)
    return {
        "request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": lower}],
            "sort": {"field": "creation_time", "keyword": "asc"},
            "search_from": 0,
            "search_to": limit,
        }
    }


def parse_cortex_alerts(body: dict[str, Any], prev_cursor: str | None = None) -> CollectResult:
    """Alerts minus the alert_ids already ingested at the prior boundary ms.

    New cursor = {ts: max creation_time, ids: every alert_id at it} (the id set
    accumulating across polls parked on one boundary), so a later gte re-fetch
    skips them — no drops, no duplicates. Mirrors the CrowdStrike collector.
    """
    prev = _decode_boundary(prev_cursor) or {}
    seen = set(prev.get("ids") or [])
    prev_ts = prev.get("ts")

    payloads: list[dict[str, Any]] = []
    max_ms: int | None = None
    ids_at_max: list[str] = []
    for a in (body.get("reply") or {}).get("alerts") or []:
        if not isinstance(a, dict) or a.get("alert_id") in seen:
            continue  # already ingested at the previous boundary timestamp
        payloads.append(a)
        ct, aid = a.get("creation_time"), a.get("alert_id")
        if not isinstance(ct, (int, float)):
            continue
        ct = int(ct)
        if max_ms is None or ct > max_ms:
            max_ms, ids_at_max = ct, [aid]
        elif ct == max_ms:
            ids_at_max.append(aid)

    cursor = None
    if max_ms is not None:
        ids = set(ids_at_max)
        if prev_ts == max_ms:
            ids |= seen
        cursor = json.dumps({"ts": max_ms, "ids": sorted(i for i in ids if i)})
    return CollectResult(payloads=payloads, cursor=cursor, detail=f"pulled {len(payloads)} alerts")


class CortexXdrCollector:
    vendor = "cortex_xdr"
    source = "cortex_xdr"

    def __init__(self, credentials: dict[str, Any], *, timeout: float = 20.0):
        self._auth_id = credentials.get("api_key_id", "")
        self._api_key = credentials.get("api_key", "")
        self._timeout = timeout

    async def collect(
        self, connector: Connector, cursor: str | None, since: str, *, limit: int
    ) -> CollectResult:
        url = connector.endpoint_url.rstrip("/") + "/public_api/v1/alerts/get_alerts_multi_events/"
        headers = {"x-xdr-auth-id": self._auth_id, "Authorization": self._api_key}
        body = build_cortex_filters(cursor, since, limit)
        async with httpx.AsyncClient(verify=connector.verify_tls, timeout=self._timeout) as client:
            resp = await client.post(url, headers=headers, json=body)
        resp.raise_for_status()
        return parse_cortex_alerts(resp.json(), cursor)


# vendor -> factory(credentials) -> Collector. A vendor is pollable only if it
# appears here AND has a normalizer registered for its `source`.
_COLLECTORS: dict[str, Any] = {
    WazuhCollector.vendor: WazuhCollector,
    CrowdStrikeCollector.vendor: CrowdStrikeCollector,
    CortexXdrCollector.vendor: CortexXdrCollector,
}


def get_collector(vendor: str, credentials: dict[str, Any]) -> Collector | None:
    factory = _COLLECTORS.get(vendor)
    return factory(credentials) if factory else None


def is_pollable(vendor: str) -> bool:
    return vendor in _COLLECTORS
