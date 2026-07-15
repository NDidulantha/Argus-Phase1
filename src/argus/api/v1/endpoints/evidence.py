"""Evidence object endpoints: trigger correlation, list scored evidence,
drill into one, run + replay persisted investigations."""

import json
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import Entity, EvidenceObject, Investigation, MitreTechnique
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.services.correlation import correlate_tenant
from argus.services.investigation import (
    run_investigation,
    run_to_completion,
    serialize_investigation,
)
from argus.services.rag import embed_evidence, find_similar
from argus.services.reasoning_providers import available_providers

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

    model_config = {"from_attributes": True}


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
    status: Annotated[
        str | None, Query(pattern=r"^(open|acknowledged|dismissed|escalated)$")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EvidenceListOut:
    async with tenant_session(current.tenant_id) as s:
        filt = [EvidenceObject.score >= min_score]
        if status is not None:
            filt.append(EvidenceObject.status == status)
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


class EvidenceStatusIn(BaseModel):
    status: Literal["open", "acknowledged", "dismissed", "escalated"]


@router.patch("/{evidence_id}", response_model=EvidenceOut)
async def set_evidence_status(
    evidence_id: int,
    body: EvidenceStatusIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> EvidenceOut:
    """Triage an alert. Non-open objects survive correlation reruns, and
    their host/window is not resurrected as a fresh open alert."""
    async with tenant_session(current.tenant_id) as s:
        obj = await s.get(EvidenceObject, evidence_id)
        if obj is None:
            raise HTTPException(404, "Evidence object not found")
        obj.status = body.status
        obj.updated_at = datetime.now(UTC)
        await s.flush()
        out = EvidenceOut.model_validate(obj)
    return out


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


class InvestigateIn(BaseModel):
    directives: list[str] = Field(default_factory=list, max_length=10)


class InvestigateOut(BaseModel):
    evidence_id: int
    investigation_id: int
    narrative: str
    provider: str
    model: str
    techniques: list[dict]
    similar_count: int
    grounded: bool
    unsupported_terms: list[str]  # unsupported artifact / MITRE claims
    directives: list[str]
    stages: list[dict]


class InvestigationRunOut(BaseModel):
    investigation_id: int
    evidence_id: int
    status: str
    provider: str | None
    model: str | None
    narrative: str | None
    grounded: bool | None
    unsupported_terms: list[str]
    directives: list[str]
    stages: list[dict]
    started_at: str | None
    finished_at: str | None
    duration_ms: int | None


class ProvidersOut(BaseModel):
    providers: list[str]
    default: str


@router.get("/reasoning/providers", response_model=ProvidersOut)
async def reasoning_providers(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ProvidersOut:
    from argus.core.config import get_settings

    return ProvidersOut(
        providers=available_providers(), default=get_settings().reasoning_provider
    )


@router.post("/{evidence_id}/investigate", response_model=InvestigateOut)
async def investigate(
    evidence_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
    provider: Annotated[str | None, Query(pattern=r"^(ollama|anthropic)$")] = None,
    body: InvestigateIn | None = None,
) -> InvestigateOut:
    """Run the AI reasoning pipeline over a curated evidence object and
    return an explainable, analyst-ready narrative. Local (Ollama) by
    default. The run is persisted; analyst directives steer the prompt."""
    final = await run_to_completion(
        current.tenant_id,
        evidence_id,
        provider,
        body.directives if body else None,
        created_by=current.user_id,
    )
    if final["type"] == "error":
        raise HTTPException(final["status_code"], final["detail"])
    inv = final["investigation"]
    return InvestigateOut(
        evidence_id=evidence_id,
        investigation_id=inv["investigation_id"],
        narrative=inv["narrative"],
        provider=inv["provider"],
        model=inv["model"],
        techniques=final["techniques"],
        similar_count=final["similar_count"],
        grounded=inv["grounded"],
        unsupported_terms=inv["unsupported_terms"],
        directives=inv["directives"],
        stages=inv["stages"],
    )


@router.post("/{evidence_id}/investigate/stream")
async def investigate_stream(
    evidence_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
    provider: Annotated[str | None, Query(pattern=r"^(ollama|anthropic)$")] = None,
    body: InvestigateIn | None = None,
) -> StreamingResponse:
    """The same pipeline as SSE: one event per stage, then complete/error —
    the workspace's reasoning stream fills in live, with server timestamps."""

    async def events():
        async for event in run_investigation(
            current.tenant_id,
            evidence_id,
            provider,
            body.directives if body else None,
            created_by=current.user_id,
        ):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{evidence_id}/investigations", response_model=list[InvestigationRunOut])
async def investigation_history(
    evidence_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
) -> list[InvestigationRunOut]:
    """Past runs for this evidence object, newest first — investigations
    are auditable records, not ephemeral chat."""
    async with tenant_session(current.tenant_id) as s:
        if await s.get(EvidenceObject, evidence_id) is None:
            raise HTTPException(404, "Evidence object not found")
        rows = (
            await s.scalars(
                select(Investigation)
                .where(Investigation.evidence_id == evidence_id)
                .order_by(Investigation.started_at.desc(), Investigation.id.desc())
                .limit(limit)
            )
        ).all()
        return [InvestigationRunOut(**serialize_investigation(r)) for r in rows]
