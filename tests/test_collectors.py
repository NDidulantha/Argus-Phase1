"""Collector query/parse logic — the pure parts, no live indexer."""

from argus.connectors.collectors import (
    build_alert_filter,
    build_cortex_filters,
    build_wazuh_query,
    get_collector,
    parse_cortex_alerts,
    parse_crowdstrike_alerts,
    parse_wazuh_hits,
)


def test_query_uses_cursor_when_present():
    q = build_wazuh_query("2026-07-19T10:00:00Z", "2026-07-19T09:00:00Z", 500)
    assert q["query"]["range"]["@timestamp"]["gt"] == "2026-07-19T10:00:00Z"
    assert q["size"] == 500
    assert q["sort"] == [{"@timestamp": {"order": "asc"}}]  # oldest first => monotonic cursor


def test_query_falls_back_to_since_on_first_run():
    q = build_wazuh_query(None, "2026-07-19T09:00:00Z", 100)
    assert q["query"]["range"]["@timestamp"]["gt"] == "2026-07-19T09:00:00Z"
    assert q["size"] == 100


def test_parse_extracts_sources_and_advances_cursor_to_max():
    body = {
        "hits": {
            "hits": [
                {"_source": {"@timestamp": "2026-07-19T10:00:01Z", "rule": {"id": "1"}}},
                {"_source": {"@timestamp": "2026-07-19T10:00:03Z", "rule": {"id": "2"}}},
                {"_source": {"@timestamp": "2026-07-19T10:00:02Z", "rule": {"id": "3"}}},
            ]
        }
    }
    result = parse_wazuh_hits(body)
    assert len(result.payloads) == 3
    assert result.cursor == "2026-07-19T10:00:03Z"  # max, not last


def test_parse_empty_leaves_cursor_none():
    result = parse_wazuh_hits({"hits": {"hits": []}})
    assert result.payloads == []
    assert result.cursor is None


def test_shipped_vendors_have_collectors():
    assert get_collector("wazuh", {"username": "u", "password": "p"}) is not None
    assert get_collector("crowdstrike", {"client_id": "i", "client_secret": "s"}) is not None
    assert get_collector("cortex_xdr", {"api_key_id": "i", "api_key": "k"}) is not None
    assert get_collector("sentinel", {}) is None  # planned, no collector yet


def test_crowdstrike_filter_uses_cursor_then_since():
    assert build_alert_filter("2026-07-19T10:00:00Z", "x") == "timestamp:>'2026-07-19T10:00:00Z'"
    assert build_alert_filter(None, "2026-07-19T09:00:00Z") == "timestamp:>'2026-07-19T09:00:00Z'"


def test_crowdstrike_parse_extracts_alerts_and_max_cursor():
    body = {
        "resources": [
            {"composite_id": "a", "timestamp": "2026-07-19T10:00:01Z"},
            {"composite_id": "b", "timestamp": "2026-07-19T10:00:04Z"},
            {"composite_id": "c", "timestamp": "2026-07-19T10:00:02Z"},
        ]
    }
    result = parse_crowdstrike_alerts(body)
    assert len(result.payloads) == 3
    assert result.cursor == "2026-07-19T10:00:04Z"


def test_crowdstrike_parse_empty_is_a_noop():
    result = parse_crowdstrike_alerts({"resources": []})
    assert result.payloads == []
    assert result.cursor is None


def test_cortex_filter_uses_cursor_as_int_and_since_as_ms():
    q = build_cortex_filters("1700000000000", "x", 50)
    assert q["request_data"]["filters"][0] == {
        "field": "creation_time", "operator": "gte", "value": 1700000000000,
    }
    assert q["request_data"]["sort"] == {"field": "creation_time", "keyword": "asc"}
    # first run: ISO `since` is converted to epoch ms
    q2 = build_cortex_filters(None, "2026-07-19T00:00:00Z", 10)
    assert q2["request_data"]["filters"][0]["value"] == 1784419200000


def test_cortex_parse_advances_cursor_past_max():
    body = {"reply": {"alerts": [
        {"alert_id": "1", "creation_time": 1700000001000},
        {"alert_id": "2", "creation_time": 1700000003000},
        {"alert_id": "3", "creation_time": 1700000002000},
    ]}}
    result = parse_cortex_alerts(body)
    assert len(result.payloads) == 3
    assert result.cursor == "1700000003001"  # max + 1 ms so gte never re-pulls it


def test_cortex_parse_empty_is_a_noop():
    result = parse_cortex_alerts({"reply": {"alerts": []}})
    assert result.payloads == []
    assert result.cursor is None
