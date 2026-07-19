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


def test_powershell_process_creation():
    e = _event(attributes={"event_id": 1, "process_image": "c:\\windows\\powershell.exe"})
    matches = {m.technique_id: m.confidence for m in classify(e)}
    assert matches["T1059.001"] == 60


def test_powershell_scriptblock_log():
    e = _event(attributes={"event_id": 4104, "provider": "Microsoft-Windows-PowerShell"})
    matches = {m.technique_id: m.confidence for m in classify(e)}
    assert matches["T1059.001"] == 55


def test_powershell_side_effects_not_execution():
    # Sysmon registry write (EID 12) by powershell.exe and module logging
    # (EID 4103) are side-effect noise, not execution evidence: the old
    # catch-all tagged 167k of these on the APT29 evals.
    reg = _event(attributes={"event_id": 12, "process_image": "c:\\...\\powershell.exe"})
    modlog = _event(attributes={"event_id": 4103, "provider": "Microsoft-Windows-PowerShell"})
    for e in (reg, modlog):
        assert "T1059.001" not in {m.technique_id for m in classify(e)}


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


def test_wmi_event_subscription_persistence():
    for eid in (19, 20, 21):
        e = _event(attributes={"event_id": eid})
        assert "T1546.003" in {m.technique_id for m in classify(e)}


def test_timestomp_by_script_host_only():
    evil = _event(
        attributes={
            "event_id": 2,
            "process_image": "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe",
        }
    )
    assert "T1070.006" in {m.technique_id for m in classify(evil)}
    # Azure guest agent rewrites timestamps constantly — must not match.
    benign = _event(
        attributes={
            "event_id": 2,
            "process_image": "C:\\WindowsAzure\\Packages\\GuestAgent\\WindowsAzureGuestAgent.exe",
        }
    )
    assert "T1070.006" not in {m.technique_id for m in classify(benign)}


def test_shell_open_command_hijack_uac_bypass():
    target = "HKU\\S-1-5-21\\Software\\Classes\\Folder\\shell\\open\\command\\(Default)"
    hijack = _event(
        attributes={
            "event_id": 13,
            "process_image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "registry_target": target,
        }
    )
    assert "T1548.002" in {m.technique_id for m in classify(hijack)}
    # svchost / Office register file associations on the same keys — benign.
    assoc = _event(
        attributes={
            "event_id": 13,
            "process_image": "C:\\windows\\system32\\svchost.exe",
            "registry_target": target,
        }
    )
    assert "T1548.002" not in {m.technique_id for m in classify(assoc)}


def test_golden_ticket_scriptblock():
    e = _event(
        attributes={
            "event_id": 4104,
            "provider": "Microsoft-Windows-PowerShell",
            "message_excerpt": (
                "invoke-mimikatz-Evals -command '\"kerberos::golden /domain:dmevals.local\"'"
            ),
        }
    )
    ids = {m.technique_id for m in classify(e)}
    assert {"T1558.001", "T1003.001"} <= ids


def test_collection_tooling_scriptblocks():
    cases = {
        "Invoke-ScreenCapture;Start-Sleep -Seconds 3": "T1113",
        "Get-Clipboard ScriptBlock ID: df281a21": "T1115",
        "function Get-Keystrokes { logs keys pressed }": "T1056.001",
        "function Get-PrivateKeys { $mypwd = ConvertTo-SecureString }": "T1552.004",
    }
    for text, tid in cases.items():
        e = _event(attributes={"event_id": 4104, "message_excerpt": text})
        assert tid in {m.technique_id for m in classify(e)}, tid


def test_amsi_probe_needs_powershell_source():
    ps = _event(
        attributes={
            "event_id": 4104,
            "provider": "Microsoft-Windows-PowerShell",
            "message_excerpt": '{ if ($_.modulename -eq "amsi.dll") {echo "AMSI Detected"}}',
        }
    )
    assert "T1562.001" in {m.technique_id for m in classify(ps)}
    # benign Sysmon EID 7 image-load of amsi.dll must not match
    load = _event(
        attributes={
            "event_id": 7,
            "provider": "Microsoft-Windows-Sysmon",
            "message_excerpt": "ImageLoaded: C:\\Windows\\System32\\amsi.dll",
        }
    )
    assert "T1562.001" not in {m.technique_id for m in classify(load)}


def test_document_sweep_collection():
    e = _event(
        attributes={
            "event_id": 4104,
            "message_excerpt": (
                "$files=ChildItem -Path $env:USERPROFILE\\ -Include *.doc,*.xps,*.xls"
            ),
        }
    )
    assert "T1005" in {m.technique_id for m in classify(e)}
