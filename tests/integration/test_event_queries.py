"""Query API: filters, pagination, detail drill-down, tenant scoping."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from argus.infrastructure.db.models import Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


def _alert(ts: str, level: int, group: str, host: str) -> dict:
    return {
        "timestamp": ts,
        "rule": {"id": "r1", "level": level, "description": "d", "groups": [group]},
        "agent": {"name": host},
        "data": {"srcip": "203.0.113.45"},
    }


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _token(client, slug: str) -> str:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": slug.title(), "slug": slug}, headers=ADMIN
    )
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": f"a@{slug}.example", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "email": f"a@{slug}.example", "password": "a-strong-password!"},
    )
    return r.json()["access_token"]


@pytest.fixture
async def seeded(client):
    token = await _token(client, "travel-g")
    events = [
        _alert("2026-07-01T08:00:00+00:00", 3, "sshd", "web-01"),
        _alert("2026-07-02T09:00:00+00:00", 7, "sshd", "web-02"),
        _alert("2026-07-03T10:00:00+00:00", 12, "malware", "db-01"),
    ]
    r = await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": events},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.json()["normalized"] == 3
    return client, {"Authorization": f"Bearer {token}"}


async def test_list_returns_newest_first(seeded):
    client, auth = seeded
    r = await client.get("/api/v1/events", headers=auth)
    body = r.json()
    assert body["total"] == 3
    assert [i["host_name"] for i in body["items"]] == ["db-01", "web-02", "web-01"]


async def test_severity_and_category_filters(seeded):
    client, auth = seeded
    r = await client.get("/api/v1/events?min_severity=7", headers=auth)
    assert r.json()["total"] == 2
    r = await client.get("/api/v1/events?category=malware", headers=auth)
    assert [i["host_name"] for i in r.json()["items"]] == ["db-01"]


async def test_time_range_and_pagination(seeded):
    client, auth = seeded
    r = await client.get(
        "/api/v1/events?start=2026-07-01T12:00:00Z&end=2026-07-02T23:59:59Z", headers=auth
    )
    assert [i["host_name"] for i in r.json()["items"]] == ["web-02"]
    r = await client.get("/api/v1/events?limit=2&offset=2", headers=auth)
    body = r.json()
    assert body["total"] == 3 and len(body["items"]) == 1


async def test_detail_includes_raw_payload(seeded):
    client, auth = seeded
    event_id = (await client.get("/api/v1/events", headers=auth)).json()["items"][0]["id"]
    r = await client.get(f"/api/v1/events/{event_id}", headers=auth)
    body = r.json()
    assert body["source"] == "wazuh"
    assert body["raw_payload"]["rule"]["id"] == "r1"  # evidence drill-down works
    assert body["src_ip"] == "203.0.113.45"


async def test_other_tenants_events_are_404(seeded):
    client, auth = seeded
    event_id = (await client.get("/api/v1/events", headers=auth)).json()["items"][0]["id"]
    other = await _token(client, "cargo-h")
    r = await client.get(
        f"/api/v1/events/{event_id}", headers={"Authorization": f"Bearer {other}"}
    )
    assert r.status_code == 404  # RLS: not yours == does not exist
    r = await client.get("/api/v1/events", headers={"Authorization": f"Bearer {other}"})
    assert r.json()["total"] == 0
