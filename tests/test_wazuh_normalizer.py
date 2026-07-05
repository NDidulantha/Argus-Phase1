"""Unit tests for the Wazuh connector — pure functions, no DB."""

from argus.connectors.wazuh import WazuhNormalizer

# Realistic Wazuh alert shape (trimmed)
WAZUH_ALERT = {
    "timestamp": "2026-07-04T10:15:30.123+0000",
    "rule": {
        "id": "5710",
        "level": 10,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["syslog", "sshd", "authentication_failed"],
        "mitre": {"id": ["T1110"], "technique": ["Brute Force"]},
    },
    "agent": {"id": "003", "name": "web-server-01"},
    "data": {"srcip": "203.0.113.45", "srcuser": "adminx"},
    "location": "/var/log/auth.log",
}


def test_wazuh_alert_maps_to_normalized_event():
    n = WazuhNormalizer().normalize(WAZUH_ALERT)
    assert n.category == "syslog"
    assert n.severity == 10
    assert n.host_name == "web-server-01"
    assert n.src_ip == "203.0.113.45"
    assert n.user_name == "adminx"
    assert n.action.startswith("sshd:")
    assert n.attributes["mitre_technique_ids"] == ["T1110"]
    assert n.event_time.year == 2026


def test_malformed_timestamp_falls_back_to_now():
    n = WazuhNormalizer().normalize({"timestamp": "not-a-date", "rule": {}})
    assert n.event_time is not None
    assert n.category == "alert"


def test_empty_payload_still_normalizes():
    n = WazuhNormalizer().normalize({})
    assert n.category == "alert"
    assert n.severity is None
