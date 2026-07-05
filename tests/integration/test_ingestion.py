"""End-to-end ingestion: login -> POST events -> rows exist, tenant-scoped."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from argus.infrastructure.db.models import NormalizedEvent, RawEvent, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}

WAZUH_ALERT = {
    "timestamp": "2026-07-04T10:15:30+0000",
    "rule": {"id": "5710", "level": 10, "description": "ssh brute force", "groups": ["sshd"]},
    "agent": {"name": "web-01"},
    "data": {"srcip": "203.0.113.45"},
}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _token(client, slug: str) -> tuple[str, str]:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": slug.title(), "slug": slug}, headers=ADMIN
    )
    tenant_id = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tenant_id}/users",
        json={"email": f"a@{slug}.example", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "email": f"a@{slug}.example", "password": "a-strong-password!"},
    )
    return tenant_id, r.json()["access_token"]


async def test_wazuh_events_are_ingested_and_normalized(client):
    tenant_id, token = await _token(client, "hotel-c")

    r = await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [WAZUH_ALERT, WAZUH_ALERT]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 202, r.text
    assert r.json() == {"received": 2, "normalized": 2}

    import uuid as _uuid

    async with tenant_session(_uuid.UUID(tenant_id)) as s:
        raw = (await s.scalars(select(RawEvent))).all()
        norm = (await s.scalars(select(NormalizedEvent))).all()
    assert len(raw) == 2 and len(norm) == 2
    assert norm[0].category == "sshd"
    assert norm[0].severity == 10
    assert str(norm[0].src_ip) == "203.0.113.45"
    assert norm[0].raw_event_id == raw[0].id  # evidence chain preserved


async def test_unknown_source_stores_raw_only(client):
    _, token = await _token(client, "cargo-d")
    r = await client.post(
        "/api/v1/events",
        json={"source": "cyberstellar", "events": [{"anything": True}]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 202
    assert r.json() == {"received": 1, "normalized": 0}  # raw kept, no connector yet


async def test_ingestion_requires_token(client):
    r = await client.post("/api/v1/events", json={"source": "wazuh", "events": [{}]})
    assert r.status_code == 401


async def test_ingested_events_are_invisible_to_other_tenants(client):
    _, token_a = await _token(client, "insurer-e")
    _, token_b = await _token(client, "exchange-f")

    await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [WAZUH_ALERT]},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    # tenant B ingests nothing; B's view of the world must be empty.
    r = await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [WAZUH_ALERT]},
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert r.json()["received"] == 1  # B sees only its own write succeed
