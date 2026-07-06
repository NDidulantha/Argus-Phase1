"""Event ingestion and query endpoints.

Query scoping note: there is no WHERE tenant_id anywhere below — the
tenant_session opened from the JWT means RLS filters every query at the
database. Application code cannot forget tenant isolation here.
"""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import NormalizedEvent, RawEvent
from argus.infrastructure.db.session import tenant_session
from argus.services.ingestion import ingest_events

router = APIRouter(prefix="/events", tags=["events"])


class EventsIn(BaseModel):
    source: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class EventsOut(BaseModel):
    received: int
    normalized: int
    failed: int


class NormalizedEventOut(BaseModel):
    id: int
    raw_event_id: int | None
    event_time: datetime
    category: str
    action: str | None
    severity: int | None
    host_name: str | None
    user_name: str | None
    src_ip: str | None
    dst_ip: str | None
    attributes: dict[str, Any]

    model_config = {"from_attributes": True}

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def _inet_to_str(cls, v: Any) -> str | None:
        return None if v is None else str(v)  # asyncpg returns IPv4Address objects


class EventListOut(BaseModel):
    items: list[NormalizedEventOut]
    total: int
    limit: int
    offset: int


class EventDetailOut(NormalizedEventOut):
    source: str | None
    raw_payload: dict[str, Any] | None


@router.post("", response_model=EventsOut, status_code=202)
async def ingest(
    body: EventsIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> EventsOut:
    # tenant_id comes from the TOKEN, never from the request body.
    async with tenant_session(current.tenant_id) as session:
        result = await ingest_events(session, current.tenant_id, body.source, body.events)
    return EventsOut(
        received=result.received, normalized=result.normalized, failed=result.failed
    )


@router.get("", response_model=EventListOut)
async def list_events(
    current: Annotated[CurrentUser, Depends(get_current_user)],
    start: Annotated[datetime | None, Query(description="event_time >= start (ISO 8601)")] = None,
    end: Annotated[datetime | None, Query(description="event_time <= end (ISO 8601)")] = None,
    category: Annotated[str | None, Query(max_length=100)] = None,
    min_severity: Annotated[int | None, Query(ge=0, le=100)] = None,
    host: Annotated[str | None, Query(max_length=200, description="substring match")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventListOut:
    filters = []
    if start is not None:
        filters.append(NormalizedEvent.event_time >= start)
    if end is not None:
        filters.append(NormalizedEvent.event_time <= end)
    if category is not None:
        filters.append(NormalizedEvent.category == category)
    if min_severity is not None:
        filters.append(NormalizedEvent.severity >= min_severity)
    if host is not None:
        filters.append(NormalizedEvent.host_name.ilike(f"%{host}%"))

    async with tenant_session(current.tenant_id) as s:
        total = await s.scalar(select(func.count(NormalizedEvent.id)).where(*filters)) or 0
        rows = (
            await s.scalars(
                select(NormalizedEvent)
                .where(*filters)
                .order_by(NormalizedEvent.event_time.desc(), NormalizedEvent.id.desc())
                .limit(limit)
                .offset(offset)
            )
        ).all()
        items = [NormalizedEventOut.model_validate(r) for r in rows]

    return EventListOut(items=items, total=total, limit=limit, offset=offset)


@router.get("/{event_id}", response_model=EventDetailOut)
async def get_event(
    event_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> EventDetailOut:
    async with tenant_session(current.tenant_id) as s:
        row = (
            await s.execute(
                select(NormalizedEvent, RawEvent)
                .outerjoin(RawEvent, NormalizedEvent.raw_event_id == RawEvent.id)
                .where(NormalizedEvent.id == event_id)
            )
        ).one_or_none()
        if row is None:
            # Another tenant's event id also lands here: RLS returns no row,
            # so "not yours" and "does not exist" are indistinguishable.
            raise HTTPException(404, "Event not found")
        normalized, raw = row
        detail = EventDetailOut(
            **NormalizedEventOut.model_validate(normalized).model_dump(),
            source=raw.source if raw else None,
            raw_payload=raw.payload if raw else None,
        )
    return detail
