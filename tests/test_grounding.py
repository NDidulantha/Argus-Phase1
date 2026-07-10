"""Unit tests: the fabrication detector."""

from argus.services.grounding import check_grounding


def test_flags_invented_tool():
    # narrative mentions dumpcap/wireshark that aren't in evidence
    n = "The attacker used dumpcap.exe and wireshark.exe to capture credentials."
    r = check_grounding(n, allowed_keys={"lsass.exe", "powershell.exe"})
    assert r["grounded"] is False
    assert "dumpcap.exe" in r["unsupported_terms"]
    assert "wireshark.exe" in r["unsupported_terms"]


def test_flags_offensive_tool_word():
    n = "This looks like Mimikatz activity against LSASS."
    r = check_grounding(n, allowed_keys={"lsass.exe"})
    assert r["grounded"] is False
    assert "mimikatz" in r["unsupported_terms"]


def test_passes_when_only_allowed_names_used():
    n = "powershell.exe accessed lsass.exe, indicating credential access."
    r = check_grounding(n, allowed_keys={"powershell.exe", "lsass.exe"})
    assert r["grounded"] is True
    assert r["unsupported_terms"] == []


def test_allowed_tool_not_flagged():
    # if psexec.exe IS in the evidence, mentioning it is fine
    n = "psexec.exe was used for lateral movement."
    r = check_grounding(n, allowed_keys={"psexec.exe"})
    assert r["grounded"] is True
