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
    # Any PowerShell execution (lower confidence — could be benign admin).
    (
        "T1059.001",
        50,
        lambda f: "powershell" in f["image"]
        or "powershell" in f["provider"]
        or "powershell" in f["channel"],
    ),
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
