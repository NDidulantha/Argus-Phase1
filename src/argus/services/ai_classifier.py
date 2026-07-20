"""AI technique classifier — the Phase 3 augmentation of the rule floor.

The deterministic classifier (services/technique_rules) is a high-precision
FLOOR: it only fires on strong evidence, so a lot of genuinely suspicious but
ambiguous activity goes unmapped. This closes that long tail with an LLM —
but carefully, so it augments rather than pollutes:

  * it only looks at events NO vendor/rule tier classified;
  * it dedupes them by content signature and asks the model ONCE per distinct
    signature (LLM calls are slow — this is a batch/on-demand pass, never
    inline with ingest), fanning the answer out to the whole group;
  * every proposed technique id is validated against the real ATT&CK catalog,
    so a hallucinated "T9999" is dropped;
  * mappings are written mapping_source='ai' at a capped confidence BELOW the
    rules floor, and (by default) are quarantined out of correlation scoring
    until validated against vendor+rules.

The value-add — dedup, parse, catalog validation, capping — is all
deterministic and unit-tested; only the single provider.complete() call is
non-deterministic.
"""

import json
import re
import uuid
from dataclasses import dataclass, field

import structlog
from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.config import get_settings
from argus.domain.reasoning import ReasoningRequest
from argus.infrastructure.db.models import EventTechnique, MitreTechnique, NormalizedEvent
from argus.infrastructure.db.session import tenant_session
from argus.services.mitre import _link
from argus.services.reasoning_providers import get_reasoning_provider

log = structlog.get_logger()

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_SCAN_LIMIT = 400  # unclassified events pulled to form signatures per run

# The fields we describe to the model — the same normalized surface the
# deterministic rules read, so the AI reasons over the same evidence.
_DESCRIBE_FIELDS = (
    ("event_id", "event_id"),
    ("channel", "channel"),
    ("process_image", "process_image"),
    ("parent_image", "parent_image"),
    ("target_image", "target_image"),
    ("command_line", "command_line"),
    ("registry_target", "registry_target"),
    ("dns_query", "dns_query"),
    ("message_excerpt", "message"),
)

_SYSTEM = (
    "You are a precise MITRE ATT&CK classification assistant for a SOC "
    "platform. Given ONE security event's normalized fields, identify the "
    "ATT&CK technique ids the event evidences. Rules: only propose a technique "
    "when the fields clearly indicate it; prefer sub-techniques (T1059.001) "
    "when precise; NEVER invent technique ids; if the event looks benign or "
    "you are unsure, return an empty array. Output STRICT JSON only: an array "
    'of {"technique_id":"T####[.###]","confidence":<1-100 int>,'
    '"rationale":"<short>"}. No prose, no markdown fences.'
)


@dataclass
class Proposal:
    technique_id: str
    confidence: int
    rationale: str = ""


@dataclass
class ClassifyResult:
    signatures_examined: int = 0
    techniques_written: int = 0
    events_tagged: int = 0
    proposals: list[Proposal] = field(default_factory=list)


def _facts(event: NormalizedEvent) -> dict[str, str]:
    attrs = event.attributes or {}
    out: dict[str, str] = {}
    for attr_key, label in _DESCRIBE_FIELDS:
        val = attrs.get(attr_key)
        if val:
            out[label] = str(val)[:300]
    if event.action:
        out["action"] = str(event.action)[:200]
    if event.category:
        out.setdefault("channel", str(event.category))
    return out


def _signature(facts: dict[str, str]) -> str:
    """Stable key so near-identical events are classified once, then fanned out."""
    parts = [
        facts.get("channel", ""),
        facts.get("event_id", ""),
        facts.get("process_image", ""),
        facts.get("parent_image", ""),
        facts.get("command_line", "")[:120],
        facts.get("registry_target", ""),
        facts.get("dns_query", ""),
    ]
    return "|".join(p.lower() for p in parts)


def _describe(facts: dict[str, str]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in facts.items())


def _extract_json_array(text: str) -> list:
    """Pull the JSON array out of a model response (tolerant of stray prose /
    ```json fences). Returns [] on anything unparseable — never raises."""
    if not text:
        return []
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end < start:
        return []
    try:
        value = json.loads(text[start : end + 1])
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def parse_proposals(text: str, valid_ids: set[str], cap: int) -> list[Proposal]:
    """Validate model output: real ATT&CK ids only, confidence clamped <= cap."""
    proposals: list[Proposal] = []
    seen: set[str] = set()
    for item in _extract_json_array(text):
        if not isinstance(item, dict):
            continue
        tid = str(item.get("technique_id", "")).upper().strip()
        if not _TID_RE.match(tid) or tid not in valid_ids or tid in seen:
            continue  # drop hallucinated / duplicate / non-catalog ids
        try:
            conf = int(item.get("confidence", 0))
        except (TypeError, ValueError):
            conf = 0
        conf = max(1, min(conf, cap))  # AI can never outrank a rules match
        proposals.append(Proposal(tid, conf, str(item.get("rationale", ""))[:280]))
        seen.add(tid)
    return proposals


async def _valid_technique_ids(session: AsyncSession) -> set[str]:
    rows = (await session.execute(select(MitreTechnique.technique_id))).scalars().all()
    return set(rows)


async def _unclassified_events(
    session: AsyncSession, limit: int
) -> list[NormalizedEvent]:
    """Most-recent events with no technique mapping of any source yet."""
    already = select(EventTechnique.id).where(
        EventTechnique.normalized_event_id == NormalizedEvent.id
    )
    rows = await session.scalars(
        select(NormalizedEvent)
        .where(~exists(already))
        .order_by(NormalizedEvent.event_time.desc())
        .limit(limit)
    )
    return list(rows)


async def classify_tenant(
    tenant_id: uuid.UUID, max_signatures: int | None = None
) -> ClassifyResult:
    """Classify the tenant's unclassified long tail with the LLM. Returns a
    summary; each mapping is written mapping_source='ai', capped, catalog-valid."""
    settings = get_settings()
    cap = settings.ai_classify_confidence_cap
    max_sigs = max_signatures if max_signatures is not None else settings.ai_classify_max_signatures
    provider = get_reasoning_provider(settings.reasoning_provider)
    if provider is None:
        raise RuntimeError(f"reasoning provider '{settings.reasoning_provider}' unavailable")

    result = ClassifyResult()
    async with tenant_session(tenant_id) as session:
        valid_ids = await _valid_technique_ids(session)
        events = await _unclassified_events(session, _SCAN_LIMIT)

        # group unclassified events by signature; classify the biggest groups
        groups: dict[str, list[NormalizedEvent]] = {}
        facts_by_sig: dict[str, dict[str, str]] = {}
        for ev in events:
            facts = _facts(ev)
            if not facts:
                continue
            sig = _signature(facts)
            groups.setdefault(sig, []).append(ev)
            facts_by_sig.setdefault(sig, facts)
        ranked = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)[:max_sigs]

        for sig, group in ranked:
            result.signatures_examined += 1
            try:
                req = ReasoningRequest(
                    system=_SYSTEM,
                    prompt="Event fields:\n" + _describe(facts_by_sig[sig]) + "\n\nJSON array:",
                    max_tokens=400,
                    temperature=0.0,
                )
                resp = await provider.complete(req)
            except Exception as exc:  # noqa: BLE001 - one signature never kills the batch
                log.warning("ai_classify_signature_failed", error=str(exc)[:200])
                continue
            proposals = parse_proposals(resp.text, valid_ids, cap)
            if not proposals:
                continue
            result.proposals.extend(proposals)
            for ev in group:
                for p in proposals:
                    await _link(session, tenant_id, ev, p.technique_id, "ai", p.confidence)
                    result.techniques_written += 1
                result.events_tagged += 1

    log.info(
        "ai_classify_done",
        tenant_id=str(tenant_id),
        signatures=result.signatures_examined,
        events_tagged=result.events_tagged,
        techniques=result.techniques_written,
    )
    return result
