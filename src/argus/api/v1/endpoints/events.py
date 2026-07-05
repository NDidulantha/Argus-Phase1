"""Event ingestion endpoint.

Note for a later phase: human analyst JWTs work here for now, but real
connectors will get dedicated per-connector ingest API keys (machines
should not hold user credentials).
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.session import tenant_session
from argus.services.ingestion import ingest_events

router = APIRouter(prefix="/events", tags=["events"])


class EventsIn(BaseModel):
    source: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class EventsOut(BaseModel):
    received: int
    normalized: int


@router.post("", response_model=EventsOut, status_code=202)
async def ingest(
    body: EventsIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> EventsOut:
    # tenant_id comes from the TOKEN, never from the request body:
    # a client cannot claim to be another tenant.
    async with tenant_session(current.tenant_id) as session:
        result = await ingest_events(session, current.tenant_id, body.source, body.events)
    return EventsOut(received=result.received, normalized=result.normalized)
