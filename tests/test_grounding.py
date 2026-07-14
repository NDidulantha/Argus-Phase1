"""Unit tests: the fabrication detector."""

from argus.services.grounding import check_grounding, check_mitre_claims, extract_technique_ids


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


# --- MITRE claim validation -------------------------------------------------
#
# Catalog snapshots mirror the loaded ATT&CK catalog (current release:
# defense-evasion no longer exists — it was split into stealth and
# defense-impairment). Production reads these from mitre_techniques; tests
# pin the contract, not a partial hardcoded technique list.

CATALOG = {
    "T1218.011": {"name": "Rundll32", "tactics": ["stealth"]},
    "T1543.003": {"name": "Windows Service", "tactics": ["persistence", "privilege-escalation"]},
    "T1053.005": {
        "name": "Scheduled Task",
        "tactics": ["execution", "persistence", "privilege-escalation"],
    },
    "T1003.001": {"name": "LSASS Memory", "tactics": ["credential-access"]},
}

KNOWN_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
}

# The failing narrative: the reasoning model produced this against evidence
# whose only mapped technique was T1053.005 (schtasks.exe scheduled task).
# Two substantive errors: T1218.011 was never mapped to this evidence, and
# schtasks.exe was attributed to T1543.003 when scheduled tasks are
# T1053.005. ('Stealth' itself is valid current ATT&CK vocabulary and IS
# the tactic of T1218.011 — the violation is citing an unmapped technique.)
FAILING_NARRATIVE = """### 2. ATT&CK ASSESSMENT
The activity maps to the Stealth tactic (T1218.011): proxy execution was likely used to evade defenses.
schtasks.exe created a scheduled task, mapped to T1543.003 (Windows Service), establishing persistence.
"""


def test_extract_technique_ids():
    assert extract_technique_ids(FAILING_NARRATIVE) == {"T1218.011", "T1543.003"}


def test_failing_narrative_flags_unmapped_techniques():
    violations = check_mitre_claims(
        FAILING_NARRATIVE,
        evidence_technique_ids={"T1053.005"},
        catalog=CATALOG,
        known_tactics=KNOWN_TACTICS,
    )
    assert (
        "incorrect MITRE claim: T1218.011 is cited but not mapped to this evidence"
        in violations
    )
    assert (
        "incorrect MITRE claim: T1543.003 is cited but not mapped to this evidence"
        in violations
    )


def test_failing_narrative_does_not_flag_current_vocabulary():
    # 'Stealth' is the technique's real tactic in the loaded catalog; the
    # check must not flag it just because it postdates older ATT&CK.
    violations = check_mitre_claims(
        FAILING_NARRATIVE,
        evidence_technique_ids={"T1053.005"},
        catalog=CATALOG,
        known_tactics=KNOWN_TACTICS,
    )
    assert not any("'Stealth'" in v or "'stealth'" in v for v in violations)


def test_nonexistent_technique_id_flagged():
    violations = check_mitre_claims(
        "This resembles T9999 activity.",
        evidence_technique_ids=set(),
        catalog={},
        known_tactics=KNOWN_TACTICS,
    )
    assert violations == ["incorrect MITRE claim: T9999 is not in the ATT&CK catalog"]


def test_invented_tactic_name_flagged():
    n = "The attacker relied on the Quantum Evasion tactic (T1053.005)."
    violations = check_mitre_claims(
        n, evidence_technique_ids={"T1053.005"}, catalog=CATALOG, known_tactics=KNOWN_TACTICS
    )
    assert "incorrect MITRE claim: 'Quantum Evasion' is not an ATT&CK tactic" in violations


def test_retired_tactic_vocabulary_flagged():
    # defense-evasion is not in the current catalog vocabulary — a model
    # trained on older ATT&CK citing it should surface as a violation.
    n = "T1218.011 falls under the Defense Evasion tactic."
    violations = check_mitre_claims(
        n, evidence_technique_ids={"T1218.011"}, catalog=CATALOG, known_tactics=KNOWN_TACTICS
    )
    assert "incorrect MITRE claim: 'Defense Evasion' is not an ATT&CK tactic" in violations


def test_real_tactic_attached_to_wrong_technique_flagged():
    n = "Tactics: credential-access. T1053.005 was used for credential access here."
    violations = check_mitre_claims(
        n, evidence_technique_ids={"T1053.005"}, catalog=CATALOG, known_tactics=KNOWN_TACTICS
    )
    assert any(
        v.startswith("incorrect MITRE claim: 'credential-access' is not a tactic of T1053.005")
        for v in violations
    )


def test_tactic_pairs_with_nearest_technique_not_cross_product():
    n = "T1053.005 (persistence) was followed by T1003.001 (credential access)."
    violations = check_mitre_claims(
        n,
        evidence_technique_ids={"T1053.005", "T1003.001"},
        catalog=CATALOG,
        known_tactics=KNOWN_TACTICS,
    )
    assert violations == []


def test_correct_narrative_passes_clean():
    n = """### ATT&CK ASSESSMENT
ATT&CK tactics: persistence, privilege-escalation.
schtasks.exe registered a scheduled task, T1053.005 (Scheduled Task), a persistence mechanism.
"""
    violations = check_mitre_claims(
        n, evidence_technique_ids={"T1053.005"}, catalog=CATALOG, known_tactics=KNOWN_TACTICS
    )
    assert violations == []


def test_prose_use_of_the_word_tactics_not_flagged():
    n = "Multiple evasive tactics were observed on this host. T1053.005 persisted."
    violations = check_mitre_claims(
        n, evidence_technique_ids={"T1053.005"}, catalog=CATALOG, known_tactics=KNOWN_TACTICS
    )
    assert violations == []
