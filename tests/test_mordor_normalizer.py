"""Unit tests for the Security Datasets (Mordor) normalizer."""

from argus.connectors.mordor import MordorNormalizer

SYSMON_EVENT = {
    "@timestamp": "2020-08-07T14:35:23.080Z",
    "EventID": 3,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "SourceName": "Microsoft-Windows-Sysmon",
    "Hostname": "WORKSTATION5.theshire.local",
    "User": "THESHIRE\\pgustavo",
    "Message": "Network connection detected:\r\nRuleName: -",
    "Image": "C:\\windows\\System32\\svchost.exe",
    "SourceIp": "172.18.39.5",
    "DestinationIp": "172.18.39.6",
}


def test_maps_sysmon_fields():
    n = MordorNormalizer().normalize(SYSMON_EVENT)
    assert n.category == "Microsoft-Windows-Sysmon/Operational"
    assert n.host_name == "WORKSTATION5.theshire.local"
    assert n.user_name == "THESHIRE\\pgustavo"
    assert n.src_ip == "172.18.39.5"
    assert n.action == "Network connection detected:"  # first line of Message
    assert n.attributes["event_id"] == 3
    assert n.attributes["process_image"].endswith("svchost.exe")
    assert n.event_time.year == 2020


def test_missing_fields_fall_back():
    n = MordorNormalizer().normalize({"EventID": 4688})
    assert n.category == "windows"
    assert n.action == "EventID 4688"
    assert n.host_name is None
    assert n.event_time is not None
