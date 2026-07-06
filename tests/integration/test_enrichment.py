"""Cache-first enrichment behavior against real Postgres, fake provider."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, update

import argus.services.enrichment as enrichment_service
from argus.domain.enrichment import EnrichmentResult
from argus.infrastructure.db.models import EnrichmentCache, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


class FakeIntel:
    provider = "fakeintel"
    supported_types = frozenset({"ip"})
    calls = 0

    async def enrich(self, indicator_type: str, value: str) -> EnrichmentResult:
        FakeIntel.calls += 1
        return EnrichmentResult(
            provider=self.provider,
            indicator_type=indicator_type,
            indicator_value=value,
            score=90,
            verdict="malicious",
            raw={"hits": 3},
        )


@pytest.fixture
async def client(migrated_db, monkeypatch):
    FakeIntel.calls = 0
    monkeypatch.setattr(enrichment_service, "get_enrichers", lambda: [FakeIntel()])
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        await s.execute(delete(EnrichmentCache))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client) -> dict:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "E", "slug": "enr"}, headers=ADMIN
    )
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "a@enr.x", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": "enr", "email": "a@enr.x", "password": "a-strong-password!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_lookup_hits_provider_then_cache(client):
    auth = await _auth(client)
    body = {"indicator_type": "ip", "value": "203.0.113.66"}

    r1 = await client.post("/api/v1/enrichment/lookup", json=body, headers=auth)
    assert r1.status_code == 200
    entry = r1.json()["results"][0]
    assert (entry["verdict"], entry["cached"]) == ("malicious", False)
    assert FakeIntel.calls == 1

    r2 = await client.post("/api/v1/enrichment/lookup", json=body, headers=auth)
    assert r2.json()["results"][0]["cached"] is True
    assert FakeIntel.calls == 1  # quota protected: no second provider call


async def test_stale_cache_refreshes(client):
    auth = await _auth(client)
    body = {"indicator_type": "ip", "value": "203.0.113.67"}
    await client.post("/api/v1/enrichment/lookup", json=body, headers=auth)

    async with admin_session() as s:  # age the cache row past the TTL
        await s.execute(
            update(EnrichmentCache).values(
                fetched_at=datetime.now(UTC) - timedelta(hours=48)
            )
        )

    r = await client.post("/api/v1/enrichment/lookup", json=body, headers=auth)
    assert r.json()["results"][0]["cached"] is False
    assert FakeIntel.calls == 2  # refreshed exactly once


async def test_invalid_ip_rejected(client):
    auth = await _auth(client)
    r = await client.post(
        "/api/v1/enrichment/lookup",
        json={"indicator_type": "ip", "value": "not-an-ip"},
        headers=auth,
    )
    assert r.status_code == 422
