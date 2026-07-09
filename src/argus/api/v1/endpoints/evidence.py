"""Evidence object endpoints: trigger correlation, list scored evidence,
drill into one. Evidence objects are the analyst-ready, AI-ready unit."""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import Entity, EvidenceObject, MitreTechnique
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.services.correlation import correlate_tenant
from argus.services.rag import embed_evidence, find_similar

router = APIRouter(prefix="/evidence", tags=["evidence"])


class CorrelateOut(BaseModel):
    evidence_objects_written: int


class EvidenceOut(BaseModel):
    id: int
    host_name: str | None
    window_start: datetime
    window_end: datetime
    event_count: int
    technique_ids: list[str]
    tactics: list[str]
    score: int
    status: str

    model_config = {"from_attributes": True}


class EvidenceListOut(BaseModel):
    items: list[EvidenceOut]
    total: int


class TechniqueBrief(BaseModel):
    technique_id: str
    name: str | None
    tactics: list[str]


class EntityBrief(BaseModel):
    id: int
    entity_type: str
    entity_key: str


class EvidenceDetailOut(EvidenceOut):
    score_breakdown: dict[str, Any]
    techniques: list[TechniqueBrief]
    entities: list[EntityBrief]


@router.post("/correlate", response_model=CorrelateOut)
async def correlate(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    window_minutes: Annotated[int, Query(ge=1, le=1440)] = 30,
) -> CorrelateOut:
    async with tenant_session(current.tenant_id) as s:
        n = await correlate_tenant(s, current.tenant_id, window_minutes)
        await s.flush()
        await embed_evidence(s, current.tenant_id)
    return CorrelateOut(evidence_objects_written=n)


@router.get("", response_model=EvidenceListOut)
async def list_evidence(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    min_score: Annotated[int, Query(ge=0, le=100)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EvidenceListOut:
    async with tenant_session(current.tenant_id) as s:
        filt = [EvidenceObject.score >= min_score]
        total = await s.scalar(select(func.count(EvidenceObject.id)).where(*filt)) or 0
        rows = (
            await s.scalars(
                select(EvidenceObject)
                .where(*filt)
                .order_by(EvidenceObject.score.desc(), EvidenceObject.window_end.desc())
                .limit(limit)
            )
        ).all()
        items = [EvidenceOut.model_validate(r) for r in rows]
    return EvidenceListOut(items=items, total=total)


@router.get("/{evidence_id}", response_model=EvidenceDetailOut)
async def get_evidence(
    evidence_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> EvidenceDetailOut:
    async with tenant_session(current.tenant_id) as s:
        obj = await s.get(EvidenceObject, evidence_id)
        if obj is None:
            raise HTTPException(404, "Evidence object not found")
        entities = (
            (
                await s.scalars(
                    select(Entity).where(Entity.id.in_(obj.entity_ids))
                )
            ).all()
            if obj.entity_ids
            else []
        )
        base = EvidenceOut.model_validate(obj).model_dump()

    # technique names from the global catalog (separate, non-tenant session)
    techniques: list[TechniqueBrief] = []
    if obj.technique_ids:
        async with admin_session() as s:
            techs = (
                await s.scalars(
                    select(MitreTechnique).where(
                        MitreTechnique.technique_id.in_(obj.technique_ids)
                    )
                )
            ).all()
            by_id = {t.technique_id: t for t in techs}
        techniques = [
            TechniqueBrief(
                technique_id=tid,
                name=by_id[tid].name if tid in by_id else None,
                tactics=by_id[tid].tactics if tid in by_id else [],
            )
            for tid in obj.technique_ids
        ]

    return EvidenceDetailOut(
        **base,
        score_breakdown=obj.score_breakdown,
        techniques=techniques,
        entities=[EntityBrief.model_validate(e) for e in entities],
    )


class SimilarEntry(BaseModel):
    id: int
    host_name: str | None
    score: int
    technique_ids: list[str]
    similarity: float  # 1 - cosine distance


class SimilarOut(BaseModel):
    evidence_id: int
    similar: list[SimilarEntry]


@router.get("/{evidence_id}/similar", response_model=SimilarOut)
async def similar_evidence(
    evidence_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
    k: Annotated[int, Query(ge=1, le=20)] = 5,
) -> SimilarOut:
    """Retrieve past evidence objects similar to this one (RAG memory)."""
    async with tenant_session(current.tenant_id) as s:
        obj = await s.get(EvidenceObject, evidence_id)
        if obj is None:
            raise HTTPException(404, "Evidence object not found")
        results = await find_similar(s, current.tenant_id, evidence_id, k)
        similar = [
            SimilarEntry(
                id=o.id,
                host_name=o.host_name,
                score=o.score,
                technique_ids=o.technique_ids,
                similarity=round(1.0 - dist, 4),
            )
            for o, dist in results
        ]
    return SimilarOut(evidence_id=evidence_id, similar=similar)
