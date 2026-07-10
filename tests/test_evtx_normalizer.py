"""Unit tests: EVTX record normalization."""

from argus.connectors.evtx_normalizer import EvtxNormalizer

# Shape produced by the evtx lib for a Sysmon EID 1 process-creation record
SYSMON_PROC = {
    "Event": {
        "System": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN-VICTIM",
            "TimeCreated": {"#attributes": {"SystemTime": "2021-05-01T10:00:00.000000Z"}},
        },
        "EventData": {
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "CommandLine": "powershell -enc ABCD",
            "TargetUserName": "victim",
        },
    }
}


def test_sysmon_process_creation():
    n = EvtxNormalizer().normalize(SYSMON_PROC)
    assert n.category == "Microsoft-Windows-Sysmon/Operational"
    assert n.host_name == "WIN-VICTIM"
    assert n.attributes["event_id"] == 1
    assert n.attributes["process_image"].endswith("powershell.exe")
    assert n.attributes["parent_image"].endswith("explorer.exe")
    assert n.user_name == "victim"
    assert n.event_time.year == 2021


def test_data_list_shape():
    # some records parse EventData as a Data list of {@Name,#text}
    rec = {"Event": {"System": {"EventID": 4625, "Channel": "Security",
                                 "Computer": "DC1"},
                     "EventData": {"Data": [
                         {"@Name": "TargetUserName", "#text": "admin"},
                         {"@Name": "IpAddress", "#text": "10.0.0.5"}]}}}
    n = EvtxNormalizer().normalize(rec)
    assert n.attributes["event_id"] == 4625
    assert n.user_name == "admin"
    assert n.src_ip == "10.0.0.5"


def test_missing_fields():
    n = EvtxNormalizer().normalize({"Event": {"System": {"EventID": 7}}})
    assert n.category == "windows"
    assert n.action == "EventID 7"
