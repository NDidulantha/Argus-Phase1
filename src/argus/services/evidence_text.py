"""Render an evidence object into the compact, deterministic text that gets
embedded (for RAG) and later handed to the reasoning LLM.

This is the 'curated evidence' representation from ADR 0010: structured,
vocabulary-rich, no raw logs. Same text drives both similarity search and
the reasoning prompt, so retrieval and reasoning stay consistent.
"""

from argus.infrastructure.db.models import EvidenceObject


def render_summary(obj: EvidenceObject, technique_names: dict[str, str]) -> str:
    techs = ", ".join(
        f"{tid} ({technique_names.get(tid, tid)})" for tid in (obj.technique_ids or [])
    )
    tactics = ", ".join(obj.tactics or [])
    return (
        f"Host {obj.host_name or 'unknown'}. "
        f"Window {obj.window_start:%Y-%m-%d %H:%M} to {obj.window_end:%H:%M}. "
        f"{obj.event_count} events. "
        f"ATT&CK tactics: {tactics or 'none'}. "
        f"Techniques: {techs or 'none'}. "
        f"Risk score {obj.score}."
    )
