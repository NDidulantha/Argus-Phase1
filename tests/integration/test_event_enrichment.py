"""Enrich-by-event and enrich-by-aggregate flows with a fake provider."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

import argus.services.enrichment as enrichment_service
from argus.domain.enrichment import EnrichmentResult
from argus.infrastructure.db.models import EnrichmentCache, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


class FakeIntel:
    provider = "fakeintel"
    supported_types = frozenset({"ip", "hash"})
    calls = 0

    async def enrich(self, indicator_type, value):
        FakeIntel.calls += 1
        return EnrichmentResult(
            provider=self.provider, indicator_type=indicator_type,
            indicator_value=value, score=88, verdict="malicious", raw={},
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


async def _auth(client, slug="enrv") -> dict:
    r = await client.post("/api/v1/admin/tenants", json={"name": slug, "slug": slug}, headers=ADMIN)
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": f"a@{slug}.x", "password": "a-strong-password!"}, headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "email": f"a@{slug}.x", "password": "a-strong-password!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


WAZUH_ALERT = {
    "timestamp": "2026-07-06T10:00:00+0000",
    "rule": {"id": "5710", "level": 10, "description": "brute force", "groups": ["sshd"]},
    "agent": {"name": "web-01"},
    "data": {"srcip": "8.8.8.8"},  # public -> indicator
}


async def test_enrich_event_extracts_and_looks_up(client):
    auth = await _auth(client)
    await client.post(
        "/api/v1/events", json={"source": "wazuh", "events": [WAZUH_ALERT]}, headers=auth
    )
    event_id = (await client.get("/api/v1/events", headers=auth)).json()["items"][0]["id"]

    r = await client.post(f"/api/v1/events/{event_id}/enrich", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["indicators"][0]["value"] == "8.8.8.8"
    assert body["indicators"][0]["results"][0]["verdict"] == "malicious"
    assert FakeIntel.calls == 1

    # second enrich of the same event: served from cache
    r = await client.post(f"/api/v1/events/{event_id}/enrich", headers=auth)
    assert r.json()["indicators"][0]["results"][0]["cached"] is True
    assert FakeIntel.calls == 1


async def test_enrich_aggregate_uses_sample_event(client):
    auth = await _auth(client, "enrw")
    await client.post(
        "/api/v1/events", json={"source": "wazuh", "events": [WAZUH_ALERT] * 5}, headers=auth
    )
    agg = (await client.get("/api/v1/events/aggregates", headers=auth)).json()["items"][0]
    assert agg["count"] == 5

    r = await client.post(f"/api/v1/events/aggregates/{agg['id']}/enrich", headers=auth)
    assert r.status_code == 200
    assert r.json()["indicators"][0]["value"] == "8.8.8.8"


async def test_enrich_is_tenant_scoped(client):
    auth_a = await _auth(client, "enrx")
    auth_b = await _auth(client, "enry")
    await client.post(
        "/api/v1/events", json={"source": "wazuh", "events": [WAZUH_ALERT]}, headers=auth_a
    )
    event_id = (await client.get("/api/v1/events", headers=auth_a)).json()["items"][0]["id"]
    r = await client.post(f"/api/v1/events/{event_id}/enrich", headers=auth_b)
    assert r.status_code == 404  # RLS: not yours == does not exist
