"""Cortex XDR alert -> NormalizedEventData mapping."""

from datetime import UTC

from argus.connectors.cortex_xdr import CortexXdrNormalizer

# 1700000000000 ms = 2023-11-14T22:13:20Z
ALERT = {
    "alert_id": "42",
    "creation_time": 1700000000000,
    "severity": "high",
    "category": "Malware",
    "description": "Suspicious process injection",
    "name": "Behavioral Threat",
    "host_name": "FIN-WS-07",
    "user_name": "acme\\jdoe",
    "action_local_ip": "10.0.0.9",
    "action_remote_ip": "203.0.113.7",
    "mitre_technique_id_and_name": "T1055 - Process Injection",
    "mitre_tactic_id_and_name": "TA0005 - Defense Evasion",
    "causality_actor_process_image_name": "rundll32.exe",
    "causality_actor_process_command_line": "rundll32.exe evil.dll,Start",
}


def test_core_fields_and_epoch_ms_time():
    n = CortexXdrNormalizer().normalize(ALERT)
    assert n.event_time.year == 2023 and n.event_time.tzinfo == UTC
    assert n.host_name == "FIN-WS-07"
    assert n.user_name == "acme\\jdoe"
    assert n.src_ip == "10.0.0.9"
    assert n.dst_ip == "203.0.113.7"
    assert n.action == "Suspicious process injection"
    assert n.category == "Malware"


def test_string_severity_mapped_to_int():
    assert CortexXdrNormalizer().normalize(ALERT).severity == 3  # "high" -> 3
    assert CortexXdrNormalizer().normalize({**ALERT, "severity": "critical"}).severity == 4


def test_technique_id_parsed_from_label():
    n = CortexXdrNormalizer().normalize(ALERT)
    assert n.attributes["mitre_technique_ids"] == ["T1055"]
    assert n.attributes["command_line"] == "rundll32.exe evil.dll,Start"
    assert n.attributes["process_image"] == "rundll32.exe"


def test_technique_accepts_list_and_skips_junk():
    n = CortexXdrNormalizer().normalize(
        {**ALERT, "mitre_technique_id_and_name": ["T1003 - Dumping", "not-a-technique"]}
    )
    assert n.attributes["mitre_technique_ids"] == ["T1003"]


def test_missing_fields_do_not_crash():
    n = CortexXdrNormalizer().normalize({"alert_id": "x"})
    assert n.host_name is None
    assert n.severity is None
    assert "mitre_technique_ids" not in n.attributes
    assert n.category == "alert"  # default
