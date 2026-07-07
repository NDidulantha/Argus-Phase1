"""Evidence Graph endpoints: entities, their neighborhoods, and attack
chains reconstructed via recursive traversal."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select, text

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import Entity, EntityEdge
from argus.infrastructure.db.session import tenant_session

router = APIRouter(prefix="/graph", tags=["graph"])


class EntityOut(BaseModel):
    id: int
    entity_type: str
    entity_key: str
    display_name: str | None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class EntityListOut(BaseModel):
    items: list[EntityOut]
    total: int


class EdgeOut(BaseModel):
    src_entity_id: int
    dst_entity_id: int
    relation: str
    observation_count: int

    model_config = {"from_attributes": True}


class NeighborhoodOut(BaseModel):
    root: EntityOut
    edges: list[EdgeOut]
    entities: list[EntityOut]


@router.get("/entities", response_model=EntityListOut)
async def list_entities(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    entity_type: Annotated[str | None, Query()] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EntityListOut:
    filters = []
    if entity_type:
        filters.append(Entity.entity_type == entity_type)
    if search:
        filters.append(Entity.entity_key.ilike(f"%{search.lower()}%"))
    async with tenant_session(current.tenant_id) as s:
        total = await s.scalar(select(func.count(Entity.id)).where(*filters)) or 0
        rows = (
            await s.scalars(
                select(Entity).where(*filters).order_by(Entity.last_seen.desc()).limit(limit)
            )
        ).all()
        items = [EntityOut.model_validate(r) for r in rows]
    return EntityListOut(items=items, total=total)


@router.get("/entities/{entity_id}/neighborhood", response_model=NeighborhoodOut)
async def neighborhood(
    entity_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> NeighborhoodOut:
    """Direct relationships (1 hop) around an entity."""
    async with tenant_session(current.tenant_id) as s:
        root = await s.get(Entity, entity_id)
        if root is None:
            raise HTTPException(404, "Entity not found")
        edges = (
            await s.scalars(
                select(EntityEdge).where(
                    (EntityEdge.src_entity_id == entity_id)
                    | (EntityEdge.dst_entity_id == entity_id)
                )
            )
        ).all()
        neighbor_ids = {e.src_entity_id for e in edges} | {e.dst_entity_id for e in edges}
        neighbor_ids.discard(entity_id)
        neighbors = (
            (await s.scalars(select(Entity).where(Entity.id.in_(neighbor_ids)))).all()
            if neighbor_ids
            else []
        )
        return NeighborhoodOut(
            root=EntityOut.model_validate(root),
            edges=[EdgeOut.model_validate(e) for e in edges],
            entities=[EntityOut.model_validate(n) for n in neighbors],
        )


class ChainNode(BaseModel):
    entity_id: int
    entity_type: str
    entity_key: str
    depth: int
    relation: str | None


class ChainOut(BaseModel):
    root_entity_id: int
    max_depth: int
    chain: list[ChainNode]


@router.get("/entities/{entity_id}/chain", response_model=ChainOut)
async def attack_chain(
    entity_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
    max_depth: Annotated[int, Query(ge=1, le=8)] = 4,
) -> ChainOut:
    """Reconstruct an attack chain by traversing outbound edges from an
    entity, up to max_depth hops, using a recursive CTE. This is how the
    graph reconstructs e.g. lateral movement or a process lineage that
    flat event tables cannot express."""
    # Recursive CTE with cycle protection via a visited-path array.
    sql = text(
        """
        WITH RECURSIVE walk AS (
            SELECT e.id AS entity_id, e.entity_type, e.entity_key,
                   0 AS depth, CAST(NULL AS text) AS relation,
                   ARRAY[e.id] AS path
            FROM entities e
            WHERE e.id = :root
            UNION ALL
            SELECT c.id, c.entity_type, c.entity_key,
                   w.depth + 1, ed.relation, w.path || c.id
            FROM walk w
            JOIN entity_edges ed ON ed.src_entity_id = w.entity_id
            JOIN entities c ON c.id = ed.dst_entity_id
            WHERE w.depth < :max_depth
              AND NOT c.id = ANY(w.path)
        )
        SELECT entity_id, entity_type, entity_key, depth, relation
        FROM walk ORDER BY depth, entity_id
        """
    )
    async with tenant_session(current.tenant_id) as s:
        root = await s.get(Entity, entity_id)
        if root is None:
            raise HTTPException(404, "Entity not found")
        rows = (await s.execute(sql, {"root": entity_id, "max_depth": max_depth})).all()

    chain = [
        ChainNode(
            entity_id=r.entity_id,
            entity_type=r.entity_type,
            entity_key=r.entity_key,
            depth=r.depth,
            relation=r.relation,
        )
        for r in rows
    ]
    return ChainOut(root_entity_id=entity_id, max_depth=max_depth, chain=chain)
