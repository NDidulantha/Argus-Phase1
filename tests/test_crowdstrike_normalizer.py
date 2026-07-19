"""CrowdStrike Falcon alert -> NormalizedEventData mapping."""

from datetime import UTC

from argus.connectors.crowdstrike import CrowdStrikeNormalizer

ALERT = {
    "composite_id": "ldt:abc:123",
    "timestamp": "2026-07-19T10:00:00.000Z",
    "created_timestamp": "2026-07-19T10:00:01.000Z",
    "severity": 70,
    "severity_name": "High",
    "tactic": "Defense Evasion",
    "technique": "Masquerading",
    "technique_id": "T1036",
    "display_name": "MasqueradedFile",
    "description": "A file was masquerading as a system binary.",
    "device": {"hostname": "WIN-01", "external_ip": "203.0.113.5",
               "local_ip": "10.0.0.5", "platform_name": "Windows"},
    "user_name": "jdoe",
    "filename": "svch0st.exe",
    "cmdline": "svch0st.exe -x",
}


def test_core_fields_mapped():
    n = CrowdStrikeNormalizer().normalize(ALERT)
    assert n.event_time.year == 2026 and n.event_time.tzinfo == UTC
    assert n.host_name == "WIN-01"
    assert n.user_name == "jdoe"
    assert n.src_ip == "203.0.113.5"  # external_ip preferred over local
    assert n.severity == 70
    assert n.action == "A file was masquerading as a system binary."


def test_technique_flows_to_mitre_linker():
    n = CrowdStrikeNormalizer().normalize(ALERT)
    assert n.attributes["mitre_technique_ids"] == ["T1036"]
    assert n.attributes["command_line"] == "svch0st.exe -x"
    assert n.attributes["process_image"] == "svch0st.exe"


def test_missing_technique_omits_mitre_key():
    n = CrowdStrikeNormalizer().normalize({"timestamp": "2026-07-19T10:00:00Z", "device": {}})
    assert "mitre_technique_ids" not in n.attributes
    assert n.host_name is None  # empty device -> no hostname, no crash


def test_falls_back_to_created_timestamp_and_display_name():
    n = CrowdStrikeNormalizer().normalize(
        {"created_timestamp": "2026-07-19T11:00:00Z", "display_name": "X", "device": {}}
    )
    assert n.event_time.hour == 11
    assert n.action == "X"
