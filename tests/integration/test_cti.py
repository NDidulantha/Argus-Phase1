"""CTI lookup: cache-first, cited findings, with a fake provider."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

import argus.services.cti as cti_service
from argus.domain.cti import CTIFinding
from argus.infrastructure.db.models import CTICache, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


class FakeCTI:
    provider = "faketi"
    supported_types = frozenset({"ip"})
    calls = 0

    async def lookup(self, indicator_type, value):
        FakeCTI.calls += 1
        return CTIFinding(
            provider="faketi", indicator_type=indicator_type, indicator_value=value,
            found=True, malware=["Emotet"], threat_actors=["TA542"],
            reference_url="https://example.test/ioc/1",
            summary="Known Emotet C2.",
        )


@pytest.fixture
async def client(migrated_db, monkeypatch):
    FakeCTI.calls = 0
    monkeypatch.setattr(cti_service, "get_cti_providers", lambda: [FakeCTI()])
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        await s.execute(delete(CTICache))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client) -> dict:
    r = await client.post("/api/v1/admin/tenants", json={"name": "C", "slug": "cti"}, headers=ADMIN)
    tid = r.json()["id"]
    await client.post(f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "a@cti.x", "password": "a-strong-password!"}, headers=ADMIN)
    r = await client.post("/api/v1/auth/login",
        json={"tenant_slug": "cti", "email": "a@cti.x", "password": "a-strong-password!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_cti_lookup_returns_cited_finding_and_caches(client):
    auth = await _auth(client)
    body = {"indicator_type": "ip", "value": "5.6.7.8"}
    r1 = await client.post("/api/v1/cti/lookup", json=body, headers=auth)
    assert r1.status_code == 200, r1.text
    d = r1.json()
    assert d["any_found"] is True
    f = d["findings"][0]
    assert f["malware"] == ["Emotet"]
    assert f["reference_url"] == "https://example.test/ioc/1"  # citation present
    assert FakeCTI.calls == 1

    r2 = await client.post("/api/v1/cti/lookup", json=body, headers=auth)
    assert r2.json()["any_found"] is True
    assert FakeCTI.calls == 1  # served from cache


async def test_invalid_cve_rejected(client):
    auth = await _auth(client)
    r = await client.post("/api/v1/cti/lookup",
        json={"indicator_type": "cve", "value": "not-a-cve"}, headers=auth)
    assert r.status_code == 422
