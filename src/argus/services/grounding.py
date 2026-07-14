"""Post-generation grounding check.

An LLM prompt can ASK for grounding; it cannot GUARANTEE it. This module
verifies, deterministically, that a narrative did not invent security
artifacts, and that its MITRE claims match ground truth:

1. Artifacts (process/tool names) must appear in the evidence entity set.
2. Every cited technique ID must exist in the ATT&CK catalog.
3. Every cited technique ID must be one actually mapped to this evidence.
4. Tactic names must be real ATT&CK tactics — judged against the LOADED
   catalog, never a hardcoded list, because tactic vocabulary changes
   across ATT&CK releases (defense-evasion was split into stealth /
   defense-impairment) — and must be correct for the technique they are
   attached to.

Result is advisory metadata attached to the investigation (grounded:
true/false + the specific unsupported claims), so analysts see exactly
where the AI may have over-reached. This is explainability applied to the
AI itself — a core requirement, not a nicety.
"""

import re
from typing import Any

# Executable / tool tokens the model might fabricate. We look for anything
# shaped like a Windows binary or a well-known offensive tool name.
_EXE_RE = re.compile(r"\b([a-z0-9_.-]+\.(?:exe|dll|ps1|bat|vbs|sys))\b", re.IGNORECASE)

# Known offensive/tool names that are red flags if unsupported by evidence.
_TOOL_WORDS = {
    "mimikatz", "wireshark", "dumpcap", "cobalt", "cobaltstrike", "metasploit",
    "psexec", "bloodhound", "rubeus", "sharphound", "procdump", "lazagne",
    "nmap", "netcat", "ncat", "empire", "covenant",
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Leading filler stripped from "<Phrase> tactic" candidates — articles plus
# capitalized sentence-starters that precede 'tactic(s)' in ordinary prose.
_PHRASE_STOPWORDS = {
    "the", "a", "an", "this", "that", "these", "those", "its", "their",
    "under", "of", "via", "using", "with", "and", "or", "known",
    "multiple", "several", "many", "various", "other", "different",
    "similar", "additional", "common", "further", "observed", "advanced",
    "sophisticated", "evasive", "defensive", "offensive", "novel", "attack",
}

# Slugs that look like tactic candidates but are prose, not claims.
_CANDIDATE_IGNORE = {"attck", "att-ck", "mitre", "mitre-attck", "ttp", "ttps", "none", "n-a", "na"}


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


def extract_technique_ids(text: str) -> set[str]:
    return set(_TECHNIQUE_RE.findall(text))


def _slug(name: str) -> str:
    """'Defense Impairment' -> 'defense-impairment' (catalog tactic form)."""
    return "-".join(re.sub(r"[^a-z0-9 -]", "", name.lower()).split())


def _tactic_candidates(text: str) -> set[str]:
    """Phrases the narrative uses AS tactic names.

    Precision-first (same philosophy as the technique rules): only firm
    tactic contexts count — 'tactics: x, y' lists, 'tactic called X', and
    '<Title Case> tactic' in a sentence that also cites a technique ID.
    Loose prose like 'evasive tactics were used' is not a checkable claim.
    """
    candidates: set[str] = set()

    for m in re.finditer(r"tactics?\s*:\s*([^\n.;]{1,150})", text, re.IGNORECASE):
        for piece in re.split(r",|/|\band\b|&", m.group(1)):
            cleaned = piece.strip(" \t*_'\"“”()[]-")
            if cleaned:
                candidates.add(cleaned)

    for m in re.finditer(
        r"tactics?\s+(?:called|named)\s+['\"“]?([A-Za-z][A-Za-z -]{1,40}?)['\"”]?(?=[\s.,;)]|$)",
        text,
        re.IGNORECASE,
    ):
        candidates.add(m.group(1).strip())

    for line in text.splitlines():
        if not _TECHNIQUE_RE.search(line):
            continue
        # Consecutive Title-Case words immediately before 'tactic':
        # 'the Stealth tactic' is a claim, 'evasive tactics' is prose.
        for m in re.finditer(
            r"((?:[A-Z][A-Za-z&-]*)(?:\s+(?:[A-Z][A-Za-z&-]*|and|of)){0,3})\s+tactics?\b",
            line,
        ):
            tokens = m.group(1).split()
            while tokens and tokens[0].lower() in _PHRASE_STOPWORDS:
                tokens.pop(0)
            while tokens and tokens[-1].lower() in {"and", "of"}:
                tokens.pop()
            if tokens:
                candidates.add(" ".join(tokens))

    return candidates


def check_mitre_claims(
    narrative: str,
    evidence_technique_ids: set[str],
    catalog: dict[str, dict[str, Any]],
    known_tactics: set[str],
) -> list[str]:
    """Validate the narrative's MITRE claims against catalog ground truth.

    catalog: technique_id -> {'name': str, 'tactics': [slug, ...]} for the
    cited IDs that exist in the loaded ATT&CK catalog (absence = unknown).
    known_tactics: every tactic slug present in the loaded catalog.
    Returns violation strings, each prefixed 'incorrect MITRE claim: '.
    """
    violations: set[str] = set()
    known_slugs = {_slug(t) for t in known_tactics}

    # 2/3. cited techniques: must exist, must be mapped to this evidence
    for tid in sorted(extract_technique_ids(narrative)):
        if tid not in catalog:
            violations.add(f"incorrect MITRE claim: {tid} is not in the ATT&CK catalog")
        elif tid not in evidence_technique_ids:
            violations.add(
                f"incorrect MITRE claim: {tid} is cited but not mapped to this evidence"
            )

    # 4a. every claimed tactic name must be real (per the loaded catalog)
    for cand in _tactic_candidates(narrative):
        slug = _slug(cand)
        if slug and slug not in known_slugs and slug not in _CANDIDATE_IGNORE:
            violations.add(f"incorrect MITRE claim: '{cand}' is not an ATT&CK tactic")

    # 4b. a real tactic attached to a technique must be one of ITS tactics.
    # Attachment = same line, validated against the NEAREST technique ID so
    # 'T1053.005 (persistence) and T1003.001 (credential-access)' pairs
    # each tactic with its own technique, not the cross product.
    for line in narrative.splitlines():
        tid_positions = [
            (m.start(), m.group(0))
            for m in _TECHNIQUE_RE.finditer(line)
            if m.group(0) in catalog
        ]
        if not tid_positions:
            continue
        lowered = line.lower()
        for tactic in known_slugs:
            spoken = tactic.replace("-", " ")
            for m in re.finditer(
                rf"\b{re.escape(tactic)}\b|\b{re.escape(spoken)}\b", lowered
            ):
                _, tid = min(tid_positions, key=lambda p: abs(p[0] - m.start()))
                true_tactics = {_slug(t) for t in catalog[tid].get("tactics", [])}
                if tactic not in true_tactics:
                    listed = ", ".join(sorted(true_tactics)) or "none"
                    violations.add(
                        f"incorrect MITRE claim: '{tactic}' is not a tactic of {tid} "
                        f"(catalog: {listed})"
                    )

    return sorted(violations)
