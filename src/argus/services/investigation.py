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

import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.domain.reasoning import ReasoningRequest
from argus.infrastructure.db.models import Entity, EvidenceObject, Investigation, MitreTechnique
from argus.infrastructure.db.session import tenant_session
from argus.services.cti import lookup_cti
from argus.services.grounding import check_grounding, check_mitre_claims, extract_technique_ids
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


def _render_prompt(ctx: InvestigationContext, directives: list[str] | None = None) -> str:
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
    if directives:
        lines.append("")
        lines.append(
            "=== ANALYST DIRECTIVES (steer the assessment; evidence rules still apply) ==="
        )
        for d in directives:
            lines.append(f"- {d}")
    lines.append("")
    lines.append(_INSTRUCTIONS)
    return "\n".join(lines)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def serialize_investigation(run: Investigation) -> dict[str, Any]:
    return {
        "investigation_id": run.id,
        "evidence_id": run.evidence_id,
        "status": run.status,
        "provider": run.provider,
        "model": run.model,
        "narrative": run.narrative,
        "grounded": run.grounded,
        "unsupported_terms": run.unsupported_terms or [],
        "directives": run.directives or [],
        "stages": run.stages or [],
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "duration_ms": run.duration_ms,
    }


async def run_investigation(
    tenant_id: uuid.UUID,
    evidence_id: int,
    provider_name: str | None = None,
    directives: list[str] | None = None,
    created_by: uuid.UUID | None = None,
) -> AsyncIterator[dict[str, Any]]:
    """The staged reasoning pipeline. Yields SSE-ready events:

      {"type": "stage", "stage": ..., "detail": ..., "at": iso}
      {"type": "complete", "investigation": {...}, "techniques": [...],
       "similar_count": n}
      {"type": "error", "status_code": ..., "detail": ...}

    Every stage is persisted to the investigations row as it happens, so
    the provenance trail survives crashes and page refreshes. Sessions
    are opened per stage — never held across the (slow) provider call.
    """
    directives = [d.strip() for d in (directives or []) if d.strip()]
    stages: list[dict[str, str]] = []
    started = time.monotonic()

    def stage(name: str, detail: str) -> dict[str, Any]:
        entry = {"stage": name, "detail": detail, "at": _now_iso()}
        stages.append(entry)
        return {"type": "stage", **entry}

    # -- scope ------------------------------------------------------------
    async with tenant_session(tenant_id) as s:
        obj = await s.get(EvidenceObject, evidence_id)
        if obj is None:
            yield {"type": "error", "status_code": 404, "detail": "Evidence object not found"}
            return
        run = Investigation(
            tenant_id=tenant_id,
            evidence_id=evidence_id,
            directives=directives,
            created_by=created_by,
        )
        s.add(run)
        await s.flush()
        run_id = run.id
        evidence_technique_ids = set(obj.technique_ids or [])
        scope_detail = (
            f"evidence #{obj.id} on {obj.host_name or 'unknown host'} · "
            f"{obj.event_count} events · score {obj.score}"
        )
    yield stage("scope", scope_detail)

    async def _persist(**fields: Any) -> None:
        async with tenant_session(tenant_id) as s:
            row = await s.get(Investigation, run_id)
            row.stages = list(stages)
            for k, v in fields.items():
                setattr(row, k, v)

    try:
        # -- collect --------------------------------------------------------
        async with tenant_session(tenant_id) as s:
            obj = await s.get(EvidenceObject, evidence_id)
            ctx = await _assemble_context(s, tenant_id, obj)
        yield stage(
            "collect",
            f"{len(ctx.entities)} entities · {len(ctx.similar)} similar past evidence · "
            f"{len(ctx.cti)} CTI findings",
        )
        await _persist()

        # -- conclude (LLM; no session held) ---------------------------------
        provider = get_reasoning_provider(provider_name)
        if provider is None:
            raise RuntimeError(f"reasoning provider '{provider_name}' unavailable")
        req = ReasoningRequest(system=_SYSTEM, prompt=_render_prompt(ctx, directives))
        llm_started = time.monotonic()
        resp = await provider.complete(req)
        yield stage(
            "conclude",
            f"{resp.model} via {resp.provider} · {time.monotonic() - llm_started:.1f}s",
        )
        await _persist(provider=resp.provider, model=resp.model)

        # -- ground -----------------------------------------------------------
        allowed_keys = {e["key"] for e in ctx.entities}
        grounding = check_grounding(resp.text, allowed_keys)
        async with tenant_session(tenant_id) as s:
            catalog, known_tactics = await _mitre_ground_truth(
                s, extract_technique_ids(resp.text)
            )
        mitre_violations = check_mitre_claims(
            resp.text, evidence_technique_ids, catalog, known_tactics
        )
        unsupported = [
            f"artifact not in evidence: {t}" for t in grounding["unsupported_terms"]
        ] + mitre_violations
        grounded = len(unsupported) == 0
        yield stage(
            "ground",
            "narrative grounded"
            if grounded
            else f"{len(unsupported)} unsupported claims detected",
        )

        # -- finalize ---------------------------------------------------------
        duration_ms = int((time.monotonic() - started) * 1000)
        async with tenant_session(tenant_id) as s:
            row = await s.get(Investigation, run_id)
            row.status = "complete"
            row.narrative = resp.text
            row.grounded = grounded
            row.unsupported_terms = unsupported
            row.stages = list(stages)
            row.provider = resp.provider
            row.model = resp.model
            row.finished_at = datetime.now(UTC)
            row.duration_ms = duration_ms
            await s.flush()
            payload = serialize_investigation(row)
        yield {
            "type": "complete",
            "investigation": payload,
            "techniques": [{"id": t["id"], "name": t["name"]} for t in ctx.techniques],
            "similar_count": len(ctx.similar),
        }
    except RuntimeError as e:
        await _persist(status="failed", finished_at=datetime.now(UTC))
        yield {"type": "error", "status_code": 503, "detail": str(e)}
    except Exception as e:  # noqa: BLE001 - provider/network errors surface as 502
        await _persist(status="failed", finished_at=datetime.now(UTC))
        yield {
            "type": "error",
            "status_code": 502,
            "detail": f"reasoning provider error: {str(e)[:200]}",
        }


async def run_to_completion(
    tenant_id: uuid.UUID,
    evidence_id: int,
    provider_name: str | None = None,
    directives: list[str] | None = None,
    created_by: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Drive the pipeline and return the final complete/error event."""
    final: dict[str, Any] = {"type": "error", "status_code": 500, "detail": "no result"}
    async for event in run_investigation(
        tenant_id, evidence_id, provider_name, directives, created_by
    ):
        if event["type"] in ("complete", "error"):
            final = event
    return final


async def _mitre_ground_truth(
    session: AsyncSession, cited_ids: set[str]
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    """Catalog rows for the cited technique IDs + the full tactic
    vocabulary, both straight from the loaded ATT&CK catalog."""
    known_tactics: set[str] = set()
    for tactics in (await session.scalars(select(MitreTechnique.tactics))).all():
        known_tactics.update(tactics or [])

    catalog: dict[str, dict[str, Any]] = {}
    if cited_ids:
        rows = (
            await session.scalars(
                select(MitreTechnique).where(MitreTechnique.technique_id.in_(cited_ids))
            )
        ).all()
        catalog = {
            r.technique_id: {"name": r.name, "tactics": list(r.tactics or [])} for r in rows
        }
    return catalog, known_tactics
