"""Unit tests for signature computation."""

from argus.services.aggregation import compute_signature


def test_rule_key_wins_over_varying_action():
    a = compute_signature("cat", "host1", "command line variant A", {"event_id": 800})
    b = compute_signature("cat", "host1", "totally different text", {"event_id": 800})
    assert a == b  # stable rule key collapses varying payloads


def test_no_rule_key_falls_back_to_action():
    a = compute_signature("cat", "host1", "action A", {})
    b = compute_signature("cat", "host1", "action B", {})
    assert a != b


def test_host_separates_signatures():
    a = compute_signature("cat", "host1", "x", {"rule_id": "1"})
    b = compute_signature("cat", "host2", "x", {"rule_id": "1"})
    assert a != b
