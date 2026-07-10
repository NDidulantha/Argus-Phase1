"""Post-generation grounding check.

An LLM prompt can ASK for grounding; it cannot GUARANTEE it. This module
verifies, deterministically, that a narrative did not invent security
artifacts. It scans the model output for process/tool names and flags any
that were NOT in the evidence's allowed entity set.

Result is advisory metadata attached to the investigation (grounded:
true/false + the specific unsupported terms), so analysts see exactly
where the AI may have over-reached. This is explainability applied to the
AI itself — a core requirement, not a nicety.
"""

import re

# Executable / tool tokens the model might fabricate. We look for anything
# shaped like a Windows binary or a well-known offensive tool name.
_EXE_RE = re.compile(r"\b([a-z0-9_.-]+\.(?:exe|dll|ps1|bat|vbs|sys))\b", re.IGNORECASE)

# Known offensive/tool names that are red flags if unsupported by evidence.
_TOOL_WORDS = {
    "mimikatz", "wireshark", "dumpcap", "cobalt", "cobaltstrike", "metasploit",
    "psexec", "bloodhound", "rubeus", "sharphound", "procdump", "lazagne",
    "nmap", "netcat", "ncat", "empire", "covenant",
}


def check_grounding(narrative: str, allowed_keys: set[str]) -> dict:
    """Return {grounded: bool, unsupported: [terms]} for a narrative.

    allowed_keys = lowercased entity keys present in the evidence
    (process/host/user/ip values the model was permitted to mention).
    """
    allowed = {k.lower() for k in allowed_keys}
    # also allow the bare stem of any allowed binary (psexec.exe -> psexec)
    allowed_stems = {a.rsplit(".", 1)[0] for a in allowed}
    text = narrative.lower()
    unsupported: set[str] = set()

    # 1. binaries mentioned that weren't in the evidence
    for m in _EXE_RE.findall(text):
        name = m.lower()
        if name not in allowed:
            unsupported.add(name)

    # 2. offensive tool words not in the evidence
    for word in _TOOL_WORDS:
        if (
            re.search(rf"\b{re.escape(word)}\b", text)
            and word not in allowed
            and word not in allowed_stems
        ):
            unsupported.add(word)

    return {
        "grounded": len(unsupported) == 0,
        "unsupported_terms": sorted(unsupported),
    }
