"""The reasoning agent: turn a curated evidence object into an
analyst-ready investigation narrative.

Flow (ADR 0010 — AI reasons over curated evidence, never raw logs):
1. Deterministically assemble the evidence context: the object's summary,
   its techniques (with ATT&CK names/tactics), entities, score breakdown,
   and RAG-retrieved similar past evidence.
2. Build a structured prompt demanding an explainable verdict.
3. Call the reasoning provider (Ollama default) and return the narrative
   plus the exact context it was grounded in (for auditability).

The deterministic step owns data assembly; the LLM only interprets. This
is what makes conclusions reproducible and traceable.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.domain.reasoning import ReasoningRequest
from argus.infrastructure.db.models import Entity, EvidenceObject, MitreTechnique
from argus.services.cti import lookup_cti
from argus.services.grounding import check_grounding
from argus.services.rag import find_similar
from argus.services.reasoning_providers import get_reasoning_provider

_SYSTEM = (
    "You are a senior SOC threat-hunting analyst. You reason STRICTLY over the "
    "structured evidence provided, and NOTHING ELSE.\n"
    "HARD RULES:\n"
    "- You may ONLY name processes, hosts, users, and IPs that appear in the "
    "EVIDENCE below. If a process/tool is not listed, you MUST NOT mention it. "
    "Never introduce tool names (e.g. mimikatz, wireshark, dumpcap) unless they "
    "are explicitly in the evidence.\n"
    "- You may ONLY cite the ATT&CK technique IDs listed. Never invent IDs.\n"
    "- When you make a claim, ground it in a specific listed technique or entity.\n"
    "- If evidence is insufficient for a section, say so plainly rather than "
    "speculating with invented detail.\n"
    "- Always give a confidence level and at least one benign / false-positive "
    "explanation."
)

_INSTRUCTIONS = """Analyze the security evidence below and produce a concise
investigation assessment with these sections:

1. SUMMARY - what appears to have happened, in 2-3 sentences.
2. ATT&CK ASSESSMENT - interpret the observed techniques as a possible
   attack progression (reference the tactics shown).
3. CONFIDENCE - High / Medium / Low, with a one-line justification.
4. ALTERNATIVE EXPLANATIONS - at least one plausible benign or
   false-positive scenario.
5. RECOMMENDED NEXT STEPS - concrete actions for the analyst.

Ground every claim in the evidence. Do not introduce facts not present."""


@dataclass
class InvestigationContext:
    evidence_id: int
    summary: str
    techniques: list[dict[str, Any]]
    entities: list[dict[str, Any]]
    score: int
    score_breakdown: dict[str, Any]
    similar: list[dict[str, Any]] = field(default_factory=list)
    cti: list[dict[str, Any]] = field(default_factory=list)


async def _assemble_context(
    session: AsyncSession, tenant_id: uuid.UUID, obj: EvidenceObject
) -> InvestigationContext:
    names: dict[str, MitreTechnique] = {}
    if obj.technique_ids:
        techs = (
            await session.scalars(
                select(MitreTechnique).where(
                    MitreTechnique.technique_id.in_(obj.technique_ids)
                )
            )
        ).all()
        names = {t.technique_id: t for t in techs}
    techniques = [
        {
            "id": tid,
            "name": names[tid].name if tid in names else tid,
            "tactics": names[tid].tactics if tid in names else [],
        }
        for tid in (obj.technique_ids or [])
    ]

    entities = []
    if obj.entity_ids:
        ents = (
            await session.scalars(select(Entity).where(Entity.id.in_(obj.entity_ids)))
        ).all()
        entities = [{"type": e.entity_type, "key": e.entity_key} for e in ents][:40]

    # CTI grounding: query real-world intel for the evidence's IP/hash
    # indicators, so the narrative can cite facts instead of guessing.
    cti_findings: list[dict[str, Any]] = []
    for e in entities:
        itype = e["type"]
        if itype == "ip":
            for f in await lookup_cti(session, "ip", e["key"]):
                if f.found:
                    cti_findings.append({
                        "indicator": e["key"], "provider": f.provider,
                        "summary": f.summary, "malware": f.malware,
                        "reference": f.reference_url,
                    })
    similar_raw = await find_similar(session, tenant_id, obj.id, k=3)
    similar = [
        {
            "host": o.host_name,
            "score": o.score,
            "techniques": o.technique_ids,
            "similarity": round(1.0 - dist, 3),
        }
        for o, dist in similar_raw
    ]

    return InvestigationContext(
        evidence_id=obj.id,
        summary=obj.summary_text or "",
        techniques=techniques,
        entities=entities,
        score=obj.score,
        score_breakdown=obj.score_breakdown or {},
        similar=similar,
        cti=cti_findings,
    )


def _render_prompt(ctx: InvestigationContext) -> str:
    lines = [
        "=== EVIDENCE OBJECT ===",
        ctx.summary,
        f"Risk score: {ctx.score} (breakdown: {ctx.score_breakdown})",
        "",
        "=== ATT&CK TECHNIQUES OBSERVED ===",
    ]
    for t in ctx.techniques:
        tac = ", ".join(t["tactics"]) or "n/a"
        lines.append(f"- {t['id']} {t['name']} [tactics: {tac}]")
    lines.append("")
    lines.append("=== ENTITIES INVOLVED (the ONLY processes/hosts/users/IPs you may mention) ===")
    if ctx.entities:
        for e in ctx.entities:
            lines.append(f"- {e['type']}: {e['key']}")
    else:
        lines.append("- (no entities recorded for this evidence)")
    # explicit allow-list restated so a small model cannot miss it
    allowed = sorted({e["key"] for e in ctx.entities})
    lines.append("")
    lines.append(
        "ALLOWED NAMES (do not mention any process/host/user/IP outside this list): "
        + (", ".join(allowed) if allowed else "(none)")
    )
    if ctx.cti:
        lines.append("")
        lines.append("=== REAL-WORLD THREAT INTELLIGENCE (cite these; do not invent) ===")
        for c in ctx.cti:
            lines.append(
                f"- {c['indicator']}: {c['summary']} "
                f"[source: {c['provider']}, ref: {c.get('reference') or 'n/a'}]"
            )
    else:
        lines.append("")
        lines.append("=== REAL-WORLD THREAT INTELLIGENCE ===")
        lines.append("- No external threat intel found for the indicators in this evidence. "
                     "Do NOT speculate about known actors or campaigns.")
    if ctx.similar:
        lines.append("")
        lines.append("=== SIMILAR PAST EVIDENCE (organizational memory / RAG) ===")
        for sdict in ctx.similar:
            lines.append(
                f"- host {sdict['host']}, score {sdict['score']}, "
                f"techniques {sdict['techniques']}, similarity {sdict['similarity']}"
            )
    lines.append("")
    lines.append(_INSTRUCTIONS)
    return "\n".join(lines)


@dataclass
class InvestigationResult:
    evidence_id: int
    narrative: str
    provider: str
    model: str
    context: InvestigationContext
    grounded: bool = True
    unsupported_terms: list = field(default_factory=list)


async def investigate_evidence(
    session: AsyncSession,
    tenant_id: uuid.UUID,
    evidence_id: int,
    provider_name: str | None = None,
) -> InvestigationResult | None:
    obj = await session.get(EvidenceObject, evidence_id)
    if obj is None:
        return None

    ctx = await _assemble_context(session, tenant_id, obj)
    provider = get_reasoning_provider(provider_name)
    if provider is None:
        raise RuntimeError(f"reasoning provider '{provider_name}' unavailable")

    req = ReasoningRequest(system=_SYSTEM, prompt=_render_prompt(ctx))
    resp = await provider.complete(req)
    allowed_keys = {e["key"] for e in ctx.entities}
    grounding = check_grounding(resp.text, allowed_keys)
    return InvestigationResult(
        evidence_id=evidence_id,
        narrative=resp.text,
        provider=resp.provider,
        model=resp.model,
        context=ctx,
        grounded=grounding["grounded"],
        unsupported_terms=grounding["unsupported_terms"],
    )
