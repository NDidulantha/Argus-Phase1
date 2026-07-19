"""Collector query/parse logic — the pure parts, no live indexer."""

from argus.connectors.collectors import build_wazuh_query, get_collector, parse_wazuh_hits


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


def test_unknown_vendor_has_no_collector():
    assert get_collector("crowdstrike", {}) is None
    assert get_collector("wazuh", {"username": "u", "password": "p"}) is not None
