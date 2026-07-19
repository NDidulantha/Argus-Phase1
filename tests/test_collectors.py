"""Collector query/parse logic — the pure parts, no live indexer."""

import json

from argus.connectors.collectors import (
    build_alert_filter,
    build_cortex_filters,
    build_wazuh_query,
    get_collector,
    parse_cortex_alerts,
    parse_crowdstrike_alerts,
    parse_wazuh_hits,
)

# --- Wazuh: search_after with an [@timestamp, _id] composite cursor -------


def test_wazuh_first_run_uses_since_floor_and_composite_sort():
    q = build_wazuh_query(None, "2026-07-19T09:00:00Z", 100)
    assert q["query"]["range"]["@timestamp"]["gte"] == "2026-07-19T09:00:00Z"
    assert q["sort"] == [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}]
    assert "search_after" not in q
    assert q["size"] == 100


def test_wazuh_composite_cursor_resumes_with_search_after():
    cursor = json.dumps(["2026-07-19T10:00:03Z", "doc-42"])
    q = build_wazuh_query(cursor, "x", 500)
    assert q["search_after"] == ["2026-07-19T10:00:03Z", "doc-42"]
    assert "query" not in q  # search_after positions us; no range needed


def test_wazuh_legacy_plain_cursor_resumes_as_floor():
    # a v1 cursor (bare timestamp) still resumes, then upgrades next batch
    q = build_wazuh_query("2026-07-19T10:00:03Z", "x", 500)
    assert q["query"]["range"]["@timestamp"]["gte"] == "2026-07-19T10:00:03Z"


def test_wazuh_cursor_is_last_hits_sort_values():
    body = {
        "hits": {
            "hits": [
                {"_source": {"a": 1}, "sort": ["2026-07-19T10:00:01Z", "id1"]},
                {"_source": {"a": 2}, "sort": ["2026-07-19T10:00:03Z", "id2"]},
            ]
        }
    }
    result = parse_wazuh_hits(body)
    assert len(result.payloads) == 2
    # cursor is the greatest hit's [ts, _id] — the exact search_after for next poll
    assert json.loads(result.cursor) == ["2026-07-19T10:00:03Z", "id2"]


def test_wazuh_parse_empty_leaves_cursor_none():
    result = parse_wazuh_hits({"hits": {"hits": []}})
    assert result.payloads == []
    assert result.cursor is None


def test_shipped_vendors_have_collectors():
    assert get_collector("wazuh", {"username": "u", "password": "p"}) is not None
    assert get_collector("crowdstrike", {"client_id": "i", "client_secret": "s"}) is not None
    assert get_collector("cortex_xdr", {"api_key_id": "i", "api_key": "k"}) is not None
    assert get_collector("sentinel", {}) is None  # planned, no collector yet


# --- CrowdStrike: gte boundary + composite_id skip set --------------------


def test_crowdstrike_first_run_and_legacy_use_strict_gt():
    assert build_alert_filter(None, "2026-07-19T09:00:00Z") == "timestamp:>'2026-07-19T09:00:00Z'"
    assert build_alert_filter("2026-07-19T10:00:00Z", "x") == "timestamp:>'2026-07-19T10:00:00Z'"


def test_crowdstrike_v2_cursor_uses_gte_boundary():
    cursor = json.dumps({"ts": "2026-07-19T10:00:04Z", "ids": ["a"]})
    assert build_alert_filter(cursor, "x") == "timestamp:>='2026-07-19T10:00:04Z'"


def test_crowdstrike_parse_records_boundary_ids():
    body = {
        "resources": [
            {"composite_id": "a", "timestamp": "2026-07-19T10:00:01Z"},
            {"composite_id": "b", "timestamp": "2026-07-19T10:00:04Z"},
            {"composite_id": "c", "timestamp": "2026-07-19T10:00:04Z"},
        ]
    }
    result = parse_crowdstrike_alerts(body)
    assert len(result.payloads) == 3
    # cursor pins the max ts and every id at it, so a gte re-fetch can skip them
    assert json.loads(result.cursor) == {"ts": "2026-07-19T10:00:04Z", "ids": ["b", "c"]}


def test_crowdstrike_boundary_truncation_does_not_drop_events():
    """The v1 bug: a limit-truncated batch splits a same-timestamp cluster and
    a strict `>` drops the remainder. v2 gte + skip-set recovers it."""
    T = "2026-07-19T10:00:04Z"
    # poll 1: batch cut after a,b (both at T); c at T didn't fit
    r1 = parse_crowdstrike_alerts({"resources": [
        {"composite_id": "a", "timestamp": T}, {"composite_id": "b", "timestamp": T},
    ]})
    assert [p["composite_id"] for p in r1.payloads] == ["a", "b"]
    # poll 2: gte T re-fetches a,b and now c fits -> a,b skipped, c ingested
    r2 = parse_crowdstrike_alerts({"resources": [
        {"composite_id": "a", "timestamp": T}, {"composite_id": "b", "timestamp": T},
        {"composite_id": "c", "timestamp": T},
    ]}, r1.cursor)
    assert [p["composite_id"] for p in r2.payloads] == ["c"]  # no drop, no duplicate
    assert json.loads(r2.cursor) == {"ts": T, "ids": ["a", "b", "c"]}  # skip set accumulates
    # poll 3: gte T, nothing new -> everything skipped, cursor held
    r3 = parse_crowdstrike_alerts({"resources": [
        {"composite_id": "a", "timestamp": T}, {"composite_id": "b", "timestamp": T},
        {"composite_id": "c", "timestamp": T},
    ]}, r2.cursor)
    assert r3.payloads == []
    assert r3.cursor is None  # unchanged -> runtime keeps the held boundary cursor


def test_crowdstrike_parse_empty_is_a_noop():
    result = parse_crowdstrike_alerts({"resources": []})
    assert result.payloads == []
    assert result.cursor is None


def test_cortex_first_run_converts_iso_since_to_ms():
    q = build_cortex_filters(None, "2026-07-19T00:00:00Z", 10)
    f = q["request_data"]["filters"][0]
    assert f == {"field": "creation_time", "operator": "gte", "value": 1784419200000}
    assert q["request_data"]["sort"] == {"field": "creation_time", "keyword": "asc"}


def test_cortex_v2_cursor_and_legacy_int_both_gte():
    def _lower(cursor):
        return build_cortex_filters(cursor, "x", 50)["request_data"]["filters"][0]["value"]

    assert _lower(json.dumps({"ts": 1700000003000, "ids": ["2"]})) == 1700000003000
    assert _lower("1700000000000") == 1700000000000  # legacy max+1 integer cursor still resumes


def test_cortex_parse_records_boundary_ids():
    body = {"reply": {"alerts": [
        {"alert_id": "1", "creation_time": 1700000001000},
        {"alert_id": "2", "creation_time": 1700000003000},
        {"alert_id": "3", "creation_time": 1700000003000},
    ]}}
    result = parse_cortex_alerts(body)
    assert len(result.payloads) == 3
    assert json.loads(result.cursor) == {"ts": 1700000003000, "ids": ["2", "3"]}


def test_cortex_boundary_truncation_does_not_drop_events():
    """Same regression as CrowdStrike: a batch cut through a same-ms cluster no
    longer drops the remainder (the old max+1 idiom did)."""
    T = 1700000003000
    r1 = parse_cortex_alerts({"reply": {"alerts": [
        {"alert_id": "a", "creation_time": T}, {"alert_id": "b", "creation_time": T},
    ]}})
    assert [p["alert_id"] for p in r1.payloads] == ["a", "b"]
    # gte T re-fetches a,b and now c fits -> a,b skipped, c ingested, ids accumulate
    r2 = parse_cortex_alerts({"reply": {"alerts": [
        {"alert_id": "a", "creation_time": T}, {"alert_id": "b", "creation_time": T},
        {"alert_id": "c", "creation_time": T},
    ]}}, r1.cursor)
    assert [p["alert_id"] for p in r2.payloads] == ["c"]
    assert json.loads(r2.cursor) == {"ts": T, "ids": ["a", "b", "c"]}


def test_cortex_parse_empty_is_a_noop():
    result = parse_cortex_alerts({"reply": {"alerts": []}})
    assert result.payloads == []
    assert result.cursor is None
