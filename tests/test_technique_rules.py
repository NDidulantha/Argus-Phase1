"""Unit tests for the deterministic ATT&CK classifier."""

from types import SimpleNamespace

from argus.services.technique_rules import classify


def _event(category="", action="", attributes=None):
    return SimpleNamespace(category=category, action=action, attributes=attributes or {})


def test_lsass_access_is_credential_dumping():
    # Sysmon EID 10 accessing lsass = what Mimikatz does -> T1003.001
    e = _event(
        category="Microsoft-Windows-Sysmon/Operational",
        action="Process accessed: TargetImage: C:\\Windows\\System32\\lsass.exe",
        attributes={"event_id": 10},
    )
    ids = {m.technique_id for m in classify(e)}
    assert "T1003.001" in ids


def test_encoded_powershell():
    e = _event(
        category="Microsoft-Windows-Sysmon/Operational",
        attributes={"event_id": 1, "process_image": "C:\\...\\powershell.exe",
                    "command_line": "powershell.exe -enc SQBFAFgA"},
    )
    matches = {m.technique_id: m.confidence for m in classify(e)}
    assert matches["T1059.001"] == 85  # encoded beats plain-powershell rule


def test_plain_powershell_lower_confidence():
    e = _event(attributes={"process_image": "c:\\windows\\powershell.exe"})
    matches = {m.technique_id: m.confidence for m in classify(e)}
    assert matches["T1059.001"] == 50


def test_rundll32_lolbin():
    e = _event(attributes={"process_image": "c:\\windows\\system32\\rundll32.exe"})
    assert "T1218.011" in {m.technique_id for m in classify(e)}


def test_failed_logon_bruteforce():
    e = _event(attributes={"event_id": 4625})
    assert "T1110" in {m.technique_id for m in classify(e)}


def test_benign_event_no_match():
    e = _event(category="Application", action="routine info", attributes={"event_id": 4})
    assert classify(e) == []


def test_psexec_lateral_movement():
    e = _event(attributes={"event_id": 1, "process_image": "C:\\Windows\\PSEXESVC.exe"})
    assert "T1021.002" in {m.technique_id for m in classify(e)}


def test_create_remote_thread_is_injection():
    e = _event(
        category="Microsoft-Windows-Sysmon/Operational",
        attributes={"event_id": 8, "process_image": "C:\\evil.exe"},
    )
    assert "T1055" in {m.technique_id for m in classify(e)}


def test_sdelete_indicator_removal():
    e = _event(attributes={"event_id": 1, "process_image": "C:\\Tools\\sdelete64.exe"})
    assert "T1070.004" in {m.technique_id for m in classify(e)}


def test_sc_exe_service_creation():
    e = _event(
        attributes={
            "event_id": 4688,
            "process_image": "C:\\Windows\\System32\\sc.exe",
            "command_line": "sc.exe create evilsvc binPath= C:\\evil.exe",
        }
    )
    assert "T1543.003" in {m.technique_id for m in classify(e)}


def test_registry_run_key_persistence():
    e = _event(
        category="Microsoft-Windows-Sysmon/Operational",
        attributes={
            "event_id": 13,
            "registry_target": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
        },
    )
    assert "T1547.001" in {m.technique_id for m in classify(e)}


def test_certutil_decode():
    e = _event(
        attributes={
            "event_id": 1,
            "process_image": "C:\\Windows\\System32\\certutil.exe",
            "command_line": "certutil.exe -decode payload.b64 payload.exe",
        }
    )
    assert "T1140" in {m.technique_id for m in classify(e)}


def test_mshta_and_wscript():
    e_mshta = _event(attributes={"process_image": "C:\\Windows\\System32\\mshta.exe"})
    assert "T1218.005" in {m.technique_id for m in classify(e_mshta)}
    e_wscript = _event(attributes={"process_image": "C:\\Windows\\System32\\wscript.exe"})
    assert "T1059.005" in {m.technique_id for m in classify(e_wscript)}


def test_wmic_execution():
    e = _event(attributes={"process_image": "C:\\Windows\\System32\\wbem\\wmic.exe"})
    assert "T1047" in {m.technique_id for m in classify(e)}
