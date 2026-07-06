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
