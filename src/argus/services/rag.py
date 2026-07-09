"""Embed evidence objects and retrieve similar ones (RAG core).

Platform learning (ADR 0010, never model retraining): past evidence
objects become searchable memory. When a new investigation runs, the
reasoning agent retrieves the most similar prior evidence to ground its
analysis in organizational history.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from argus.infrastructure.db.models import EvidenceObject, MitreTechnique
from argus.services.embedding import get_embedder
from argus.services.evidence_text import render_summary


async def _technique_names(session: AsyncSession, ids: list[str]) -> dict[str, str]:
    if not ids:
        return {}
    techs = (
        await session.scalars(
            select(MitreTechnique).where(MitreTechnique.technique_id.in_(ids))
        )
    ).all()
    return {t.technique_id: t.name for t in techs}


async def embed_evidence(session: AsyncSession, tenant_id: uuid.UUID) -> int:
    """Embed all evidence objects for a tenant that lack an embedding."""
    embedder = get_embedder()
    rows = (
        await session.scalars(
            select(EvidenceObject).where(EvidenceObject.embedding.is_(None))
        )
    ).all()
    if not rows:
        return 0

    all_tids = sorted({t for r in rows for t in (r.technique_ids or [])})
    names = await _technique_names(session, all_tids)

    for obj in rows:
        summary = render_summary(obj, names)
        obj.summary_text = summary
        obj.embedding = embedder.embed(summary)
        obj.embedding_provider = embedder.provider
    return len(rows)


async def find_similar(
    session: AsyncSession, tenant_id: uuid.UUID, evidence_id: int, k: int = 5
) -> list[tuple[EvidenceObject, float]]:
    """Return up to k evidence objects most similar to the given one
    (excluding itself), with cosine distance."""
    target = await session.get(EvidenceObject, evidence_id)
    if target is None or target.embedding is None:
        return []

    distance = EvidenceObject.embedding.cosine_distance(target.embedding)
    rows = (
        await session.execute(
            select(EvidenceObject, distance.label("dist"))
            .where(EvidenceObject.id != evidence_id, EvidenceObject.embedding.is_not(None))
            .order_by(distance)
            .limit(k)
        )
    ).all()
    return [(r[0], float(r[1])) for r in rows]
