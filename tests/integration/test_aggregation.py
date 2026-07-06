"""Aggregation: repetition collapses into counted signals, tenant-scoped."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from argus.infrastructure.db.models import Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


def _alert(rule_id: str, level: int, host: str, minute: int, desc: str = "d") -> dict:
    return {
        "timestamp": f"2026-07-06T10:{minute:02d}:00+0000",
        "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["g"]},
        "agent": {"name": host},
    }


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug: str) -> dict:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": slug, "slug": slug}, headers=ADMIN
    )
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": f"a@{slug}.x", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "email": f"a@{slug}.x", "password": "a-strong-password!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_repetition_collapses_into_counted_signal(client):
    auth = await _auth(client, "agg-a")
    noise = [_alert("100210", 7, "win10", m % 60, desc=f"variant {m}") for m in range(40)]
    distinct = [_alert("60204", 10, "win10", 1), _alert("5710", 9, "web01", 2)]

    r = await client.post(
        "/api/v1/events", json={"source": "wazuh", "events": noise + distinct}, headers=auth
    )
    assert r.json()["normalized"] == 42

    r = await client.get("/api/v1/events/aggregates", headers=auth)
    body = r.json()
    assert body["total"] == 3  # 42 events -> 3 signals
    top = body["items"][0]
    assert top["count"] == 40  # rule_id keyed: varying descriptions still collapse
    assert top["severity_max"] == 7
    assert top["first_seen"] < top["last_seen"]

    r = await client.get("/api/v1/events/aggregates?min_count=10", headers=auth)
    assert r.json()["total"] == 1


async def test_same_rule_different_host_stays_separate(client):
    auth = await _auth(client, "agg-b")
    events = [_alert("5710", 9, "web01", 1), _alert("5710", 9, "web02", 2)]
    await client.post("/api/v1/events", json={"source": "wazuh", "events": events}, headers=auth)
    r = await client.get("/api/v1/events/aggregates", headers=auth)
    assert r.json()["total"] == 2  # host is part of the signature


async def test_aggregates_are_tenant_scoped(client):
    auth_a = await _auth(client, "agg-c")
    auth_b = await _auth(client, "agg-d")
    await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [_alert("1", 5, "h", 1)] * 5},
        headers=auth_a,
    )
    r = await client.get("/api/v1/events/aggregates", headers=auth_b)
    assert r.json()["total"] == 0
