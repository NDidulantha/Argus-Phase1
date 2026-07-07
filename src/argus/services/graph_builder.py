"""Evidence Graph builder: turn a normalized event into entities + edges.

Deterministic entity extraction — the stage that lets attack chains be
reconstructed as connected objects instead of isolated event rows. Entity
identity is (type, key); the same host/process/user across many events
collapses to one node whose relationships accumulate.

Example (Mimikatz): a Sysmon EID 10 where powershell.exe accesses
lsass.exe yields entities process:powershell.exe and process:lsass.exe
and an edge process --accessed--> process, reconstructable later as an
attack chain.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from argus.infrastructure.db.models import Entity, EntityEdge, NormalizedEvent


@dataclass
class _Node:
    entity_type: str
    entity_key: str
    display_name: str | None = None


@dataclass
class _Extraction:
    nodes: list[_Node] = field(default_factory=list)
    edges: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    # edge = (src_type, src_key, relation, dst_type, dst_key)


def _basename(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").split("/")[-1].lower() or path.lower()


def extract_graph(event: NormalizedEvent) -> _Extraction:
    attrs = event.attributes or {}
    ex = _Extraction()

    def add_node(t: str, key: str | None, name: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        ex.nodes.append(_Node(t, key, name or key))
        return key

    host_key = add_node("host", event.host_name)
    user_key = add_node("user", event.user_name)

    image = attrs.get("process_image")
    parent = attrs.get("parent_image")
    target = attrs.get("target_image")
    proc_key = add_node("process", _basename(image)) if image else None
    parent_key = add_node("process", _basename(parent)) if parent else None
    target_key = add_node("process", _basename(target)) if target else None

    src_ip_key = add_node("ip", str(event.src_ip) if event.src_ip else None)
    dst_ip_key = add_node("ip", str(event.dst_ip) if event.dst_ip else None)

    # --- relationships -------------------------------------------------
    if parent_key and proc_key:
        ex.edges.append(("process", parent_key, "spawned", "process", proc_key))
    if proc_key and target_key:
        ex.edges.append(("process", proc_key, "accessed", "process", target_key))
    if host_key and proc_key:
        ex.edges.append(("host", host_key, "ran", "process", proc_key))
    if user_key and host_key:
        ex.edges.append(("user", user_key, "active_on", "host", host_key))
    if host_key and dst_ip_key:
        ex.edges.append(("host", host_key, "connected_to", "ip", dst_ip_key))
    if src_ip_key and host_key:
        ex.edges.append(("ip", src_ip_key, "connected_to", "host", host_key))

    return ex


async def _upsert_entity(
    session: AsyncSession, tenant_id: uuid.UUID, node: _Node, ts: datetime
) -> int:
    stmt = pg_insert(Entity).values(
        tenant_id=tenant_id,
        entity_type=node.entity_type,
        entity_key=node.entity_key,
        display_name=node.display_name,
        first_seen=ts,
        last_seen=ts,
    )
    stmt = stmt.on_conflict_do_update(
        constraint="uq_entity_identity",
        set_={"last_seen": stmt.excluded.last_seen},
    ).returning(Entity.id)
    # ON CONFLICT ... RETURNING gives the id whether inserted or updated,
    # but only if the update actually runs; guard with a follow-up select.
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if row is not None:
        return row
    existing = await session.scalar(
        select(Entity.id).where(
            Entity.entity_type == node.entity_type, Entity.entity_key == node.entity_key
        )
    )
    return existing


async def build_graph(
    session: AsyncSession, tenant_id: uuid.UUID, event: NormalizedEvent
) -> tuple[int, int]:
    ex = extract_graph(event)
    if not ex.nodes:
        return (0, 0)

    ts = event.event_time
    ids: dict[tuple[str, str], int] = {}
    for node in ex.nodes:
        key = (node.entity_type, node.entity_key)
        if key not in ids:
            ids[key] = await _upsert_entity(session, tenant_id, node, ts)

    edge_count = 0
    for src_t, src_k, relation, dst_t, dst_k in ex.edges:
        src_id = ids.get((src_t, src_k))
        dst_id = ids.get((dst_t, dst_k))
        if src_id is None or dst_id is None:
            continue
        stmt = pg_insert(EntityEdge).values(
            tenant_id=tenant_id,
            src_entity_id=src_id,
            dst_entity_id=dst_id,
            relation=relation,
            first_seen=ts,
            last_seen=ts,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_edge_identity",
            set_={
                "observation_count": EntityEdge.observation_count + 1,
                "last_seen": stmt.excluded.last_seen,
            },
        )
        await session.execute(stmt)
        edge_count += 1

    return (len(ids), edge_count)
