"""Deterministic ATT&CK classifier.

When an event carries no vendor ATT&CK IDs, infer techniques from
normalized fields + attributes. This is the high-precision floor: rules
only fire on strong evidence, each returns a technique + confidence, and
every mapping is explainable. In Phase 3 an AI classifier augments (not
replaces) this for the ambiguous long tail.

A rule is (technique_id, confidence, predicate). Predicates read a small
normalized 'facts' dict so rules stay vendor-agnostic — the same rule
fires whether the event came from Sysmon via Mordor or via Wazuh.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from argus.infrastructure.db.models import NormalizedEvent


@dataclass(frozen=True)
class TechniqueMatch:
    technique_id: str
    confidence: int


def _facts(event: NormalizedEvent) -> dict[str, Any]:
    attrs = event.attributes or {}

    def low(key: str) -> str:
        v = attrs.get(key)
        return str(v).lower() if v is not None else ""

    return {
        "event_id": str(attrs.get("event_id") or ""),
        "channel": (event.category or "").lower(),
        "image": low("process_image"),
        "parent_image": low("parent_image"),
        "target_image": low("target_image"),
        "command_line": low("command_line"),
        "action": (event.action or "").lower(),
        "provider": low("provider"),
        "registry_target": low("registry_target"),
        "dns_query": low("dns_query"),
        # broad text field for rules that need to match indicators buried
        # in the raw message (Sysmon puts a lot only in Message).
        "message": low("message_excerpt") + " " + low("details"),
    }


# --- Rules. Ordered; all matching rules fire (an event can exhibit several
# techniques). Keep predicates strict to protect precision. ---------------
Rule = tuple[str, int, Callable[[dict[str, Any]], bool]]

_RULES: list[Rule] = [
    # Sysmon EID 10: process access to lsass.exe = credential dumping.
    # This is exactly what Mimikatz does. High confidence.
    (
        "T1003.001",
        90,
        lambda f: f["event_id"] == "10"
        and "lsass.exe" in f["target_image"] + f["action"] + f["message"],
    ),
    # PowerShell with encoded command = obfuscated execution.
    (
        "T1059.001",
        85,
        lambda f: "powershell" in f["image"] + f["provider"] + f["channel"]
        and ("-enc" in f["command_line"] or "-encodedcommand" in f["command_line"]),
    ),
    # PowerShell *execution* only: a process-creation event with a
    # powershell image, or a script-block log (EID 4104 = code the engine
    # actually compiled). Matching every event powershell.exe merely
    # touches (registry writes, DLL loads, module logs 800/4103) tagged
    # 167k events on the APT29 evals and drowned the evidence objects.
    (
        "T1059.001",
        60,
        lambda f: f["event_id"] in ("1", "4688") and "powershell" in f["image"],
    ),
    ("T1059.001", 55, lambda f: f["event_id"] == "4104"),
    # Windows cmd shell execution.
    ("T1059.003", 45, lambda f: f["image"].endswith("cmd.exe")),
    # Sysmon EID 1 process creation from Office apps = suspicious spawn.
    (
        "T1059",
        40,
        lambda f: f["event_id"] == "1"
        and any(o in f["parent_image"] for o in ("winword.exe", "excel.exe", "powerpnt.exe")),
    ),
    # rundll32 / regsvr32 = signed binary proxy execution (LOLBin).
    (
        "T1218.011",
        70,
        lambda f: f["image"].endswith("rundll32.exe"),
    ),
    (
        "T1218.010",
        70,
        lambda f: f["image"].endswith("regsvr32.exe"),
    ),
    # Failed Windows logons (EID 4625) = brute force / cred access.
    ("T1110", 60, lambda f: f["event_id"] == "4625"),
    # Scheduled task creation.
    (
        "T1053.005",
        65,
        lambda f: f["image"].endswith("schtasks.exe") or "scheduled task" in f["action"],
    ),
    # Service installation (EID 7045) = persistence / execution.
    ("T1543.003", 65, lambda f: f["event_id"] == "7045"),
    # sc.exe creating/configuring a service = service persistence/exec.
    (
        "T1543.003",
        55,
        lambda f: f["image"].endswith("sc.exe")
        and any(v in f["command_line"] for v in ("create", "config", "start")),
    ),
    # PsExec / psexesvc = remote service execution over SMB admin shares.
    # A hallmark of hands-on-keyboard lateral movement.
    (
        "T1021.002",
        75,
        lambda f: "psexec" in f["image"]
        or f["image"].endswith("psexesvc.exe")
        or "psexesvc" in f["command_line"],
    ),
    # Sysmon EID 8 CreateRemoteThread = classic process injection.
    ("T1055", 70, lambda f: f["event_id"] == "8"),
    # SDelete = secure file wipe: indicator removal / anti-forensics.
    (
        "T1070.004",
        70,
        lambda f: "sdelete" in f["image"] or "sdelete" in f["command_line"],
    ),
    # Registry Run key written (Sysmon EID 12/13) = autostart persistence.
    (
        "T1547.001",
        75,
        lambda f: "currentversion\\run" in f["registry_target"]
        or "currentversion\\runonce" in f["registry_target"],
    ),
    # certutil decoding/downloading = ingress transfer / deobfuscation LOLBin.
    (
        "T1140",
        65,
        lambda f: f["image"].endswith("certutil.exe")
        and any(v in f["command_line"] for v in ("-decode", "-urlcache", "-verifyctl")),
    ),
    # mshta executing = signed-binary proxy execution of HTA/script.
    ("T1218.005", 65, lambda f: f["image"].endswith("mshta.exe")),
    # wscript / cscript = Windows Script Host execution (VBScript/JScript).
    (
        "T1059.005",
        50,
        lambda f: f["image"].endswith("wscript.exe") or f["image"].endswith("cscript.exe"),
    ),
    # WMI process launch (wmic.exe, or WmiPrvSE spawning a child) = T1047.
    (
        "T1047",
        50,
        lambda f: f["image"].endswith("wmic.exe")
        or f["parent_image"].endswith("wmiprvse.exe"),
    ),
    # Sysmon EID 19/20/21: WMI event filter/consumer/binding = fileless
    # persistence via event subscription. Rare and almost never benign.
    ("T1546.003", 85, lambda f: f["event_id"] in ("19", "20", "21")),
    # Sysmon EID 2 from a script host = timestomping. Blanket EID 2 is
    # noise (Azure agent, ProvTool, servicing all rewrite timestamps);
    # a shell doing it is deliberate anti-forensics.
    (
        "T1070.006",
        80,
        lambda f: f["event_id"] == "2"
        and any(
            s in f["image"]
            for s in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32")
        ),
    ),
    # shell\open\command class hijack (sdclt/fodhelper-style UAC bypass):
    # an auto-elevating binary reads the hijacked verb from HKCU. Only a
    # shell/script host writing the key is hijack staging — svchost,
    # Outlook, Teams etc. register file associations there legitimately.
    (
        "T1548.002",
        80,
        lambda f: f["event_id"] in ("12", "13")
        and "shell\\open\\command" in f["registry_target"]
        and any(
            s in f["image"]
            for s in ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "reg.exe")
        ),
    ),
    # Mimikatz tradecraft in script blocks / command lines.
    (
        "T1558.001",
        90,
        lambda f: "kerberos::golden" in f["message"] + f["command_line"],
    ),
    (
        "T1003.001",
        85,
        lambda f: any(
            s in f["message"] + f["command_line"]
            for s in ("invoke-mimikatz", "sekurlsa::", "lsadump::")
        ),
    ),
    # PowerShell collection tooling (PoshC2 / PowerSploit function names
    # and the Win32 APIs they wrap).
    (
        "T1113",
        75,
        lambda f: "invoke-screencapture" in f["message"] or "copyfromscreen" in f["message"],
    ),
    ("T1115", 65, lambda f: "get-clipboard" in f["message"]),
    (
        "T1056.001",
        85,
        lambda f: "get-keystrokes" in f["message"] or "getasynckeystate" in f["message"],
    ),
    # Certificate/private-key theft from user stores.
    (
        "T1552.004",
        80,
        lambda f: "get-privatekeys" in f["message"] or "export-pfxcertificate" in f["message"],
    ),
    # PowerShell probing or disabling AMSI. Gated on a PowerShell source
    # so benign amsi.dll image-loads (Sysmon EID 7) never match.
    (
        "T1562.001",
        70,
        lambda f: "powershell" in f["provider"] + f["channel"]
        and any(s in f["message"] for s in ("amsiinitfailed", "amsiutils", "amsi.dll")),
    ),
    # Bulk document sweep of a user profile = local data collection.
    (
        "T1005",
        70,
        lambda f: "childitem" in f["message"]
        and "-include" in f["message"]
        and "*.doc" in f["message"],
    ),
]


def classify(event: NormalizedEvent) -> list[TechniqueMatch]:
    """Return the highest-confidence match per technique_id."""
    facts = _facts(event)
    best: dict[str, int] = {}
    for technique_id, confidence, predicate in _RULES:
        try:
            if predicate(facts):
                best[technique_id] = max(best.get(technique_id, 0), confidence)
        except Exception:  # noqa: BLE001 - a bad rule must never break ingestion
            continue
    return [TechniqueMatch(t, c) for t, c in best.items()]
