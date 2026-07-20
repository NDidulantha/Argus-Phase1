"""MITRE ATT&CK endpoints: technique lookup and per-tenant coverage.

Coverage = the ATT&CK heatmap data. For each technique the tenant has
seen: how many events, first/last seen, and the technique's tactics —
joined to the global catalog for names. This is what the future UI
renders as a heatmap and what lets the AI reason in ATT&CK terms.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import EventTechnique, MitreTechnique
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.services.ai_classifier import classify_tenant

router = APIRouter(prefix="/mitre", tags=["mitre"])


class TechniqueOut(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None
    url: str | None
    description: str | None

    model_config = {"from_attributes": True}


class CoverageEntry(BaseModel):
    technique_id: str
    name: str | None
    tactics: list[str]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    sources: dict[str, int]  # {"vendor": 3, "rules": 40}
    max_confidence: int


class CoverageOut(BaseModel):
    techniques_seen: int
    total_events: int
    by_source: dict[str, int]  # technique-mappings grouped by provenance
    coverage: list[CoverageEntry]


class MatrixTechnique(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool
    parent_id: str | None

    model_config = {"from_attributes": True}


@router.get("/matrix", response_model=list[MatrixTechnique])
async def matrix(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[MitreTechnique]:
    """The full catalog for the tactics × techniques matrix — coverage
    shows what a tenant HAS seen; the matrix needs everything, so the
    gaps are visible too."""
    async with admin_session() as s:
        return (
            await s.scalars(select(MitreTechnique).order_by(MitreTechnique.technique_id))
        ).all()


@router.get("/techniques/{technique_id}", response_model=TechniqueOut)
async def get_technique(
    technique_id: str,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> MitreTechnique:
    # Catalog is global reference data; admin_session (no tenant) is correct.
    async with admin_session() as s:
        tech = await s.get(MitreTechnique, technique_id.upper())
        if tech is None:
            raise HTTPException(404, "Technique not found in catalog")
        return tech


@router.get("/coverage", response_model=CoverageOut)
async def coverage(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> CoverageOut:
    # Per-tenant technique counts + provenance breakdown (RLS-scoped)...
    async with tenant_session(current.tenant_id) as s:
        rows = (
            await s.execute(
                select(
                    EventTechnique.technique_id,
                    func.count(EventTechnique.id).label("cnt"),
                    func.min(EventTechnique.event_time).label("first_seen"),
                    func.max(EventTechnique.event_time).label("last_seen"),
                    func.max(EventTechnique.confidence).label("max_conf"),
                )
                .group_by(EventTechnique.technique_id)
                .order_by(func.count(EventTechnique.id).desc())
            )
        ).all()
        source_rows = (
            await s.execute(
                select(
                    EventTechnique.technique_id,
                    EventTechnique.mapping_source,
                    func.count(EventTechnique.id).label("cnt"),
                ).group_by(EventTechnique.technique_id, EventTechnique.mapping_source)
            )
        ).all()

    sources_by_tech: dict[str, dict[str, int]] = {}
    by_source: dict[str, int] = {}
    for sr in source_rows:
        sources_by_tech.setdefault(sr.technique_id, {})[sr.mapping_source] = sr.cnt
        by_source[sr.mapping_source] = by_source.get(sr.mapping_source, 0) + sr.cnt

    # ...then decorate with global catalog metadata (separate session:
    # the catalog is not tenant data).
    catalog: dict[str, MitreTechnique] = {}
    if rows:
        async with admin_session() as s:
            techs = (
                await s.scalars(
                    select(MitreTechnique).where(
                        MitreTechnique.technique_id.in_([r.technique_id for r in rows])
                    )
                )
            ).all()
            catalog = {t.technique_id: t for t in techs}

    coverage_list = [
        CoverageEntry(
            technique_id=r.technique_id,
            name=catalog[r.technique_id].name if r.technique_id in catalog else None,
            tactics=catalog[r.technique_id].tactics if r.technique_id in catalog else [],
            event_count=r.cnt,
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            sources=sources_by_tech.get(r.technique_id, {}),
            max_confidence=r.max_conf,
        )
        for r in rows
    ]
    return CoverageOut(
        techniques_seen=len(coverage_list),
        total_events=sum(r.cnt for r in rows),
        by_source=by_source,
        coverage=coverage_list,
    )


class AiProposalOut(BaseModel):
    technique_id: str
    confidence: int
    rationale: str


class AiClassifyOut(BaseModel):
    signatures_examined: int
    events_tagged: int
    techniques_written: int
    proposals: list[AiProposalOut]


@router.post("/ai-classify", response_model=AiClassifyOut)
async def ai_classify(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> AiClassifyOut:
    """Run the AI classifier over the tenant's unclassified long tail.

    Augments the deterministic rules: only touches events no vendor/rule tier
    mapped, validates every proposal against the ATT&CK catalog, and writes
    them mapping_source='ai' at a capped confidence. These are recorded and
    visible in coverage but quarantined from alert scoring by default."""
    result = await classify_tenant(current.tenant_id)
    return AiClassifyOut(
        signatures_examined=result.signatures_examined,
        events_tagged=result.events_tagged,
        techniques_written=result.techniques_written,
        proposals=[
            AiProposalOut(
                technique_id=p.technique_id, confidence=p.confidence, rationale=p.rationale
            )
            for p in result.proposals
        ],
    )
