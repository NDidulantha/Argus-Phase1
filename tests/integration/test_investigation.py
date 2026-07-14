"""Reasoning agent flow with a FAKE provider (no Ollama needed in CI):
evidence -> curated context -> narrative, tenant-scoped."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

import argus.services.investigation as investigation_service
from argus.domain.reasoning import ReasoningResponse
from argus.infrastructure.db.models import MitreTechnique, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


class FakeProvider:
    name = "fake"

    async def complete(self, req):
        # echo that we received the curated evidence (proves grounding)
        assert "ATT&CK TECHNIQUES OBSERVED" in req.prompt
        # deliberately fabricate a tool not in the evidence
        return ReasoningResponse(
            text=("SUMMARY: credential dumping via mimikatz suspected. "
                  "lsass.exe was accessed.\nCONFIDENCE: High."),
            provider="fake",
            model="fake-1",
        )


@pytest.fixture
async def client(migrated_db, monkeypatch):
    monkeypatch.setattr(
        investigation_service, "get_reasoning_provider", lambda name=None: FakeProvider()
    )
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        await s.execute(
            pg_insert(MitreTechnique)
            .values(technique_id="T1003.001", name="LSASS Memory",
                    tactics=["credential-access"], is_subtechnique=True)
            .on_conflict_do_nothing()
        )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="inv") -> dict:
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


def _lsass(minute):
    return {"@timestamp": f"2020-08-07T14:{minute:02d}:00Z", "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS5",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "Message": "Process accessed lsass.exe"}


async def test_investigate_produces_narrative(client):
    auth = await _auth(client)
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(30), _lsass(31)]}, headers=auth)
    await client.post("/api/v1/evidence/correlate", headers=auth)
    ev = (await client.get("/api/v1/evidence", headers=auth)).json()["items"][0]

    r = await client.post(f"/api/v1/evidence/{ev['id']}/investigate", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "credential dumping" in body["narrative"].lower()
    assert body["provider"] == "fake"
    assert any(t["id"] == "T1003.001" for t in body["techniques"])
    # grounding check caught the fabricated tool name, labeled by category
    assert body["grounded"] is False
    assert "artifact not in evidence: mimikatz" in body["unsupported_terms"]


async def test_investigate_missing_evidence_404(client):
    auth = await _auth(client)
    r = await client.post("/api/v1/evidence/999999/investigate", headers=auth)
    assert r.status_code == 404


async def test_investigate_tenant_scoped(client):
    auth_a = await _auth(client, "inv-a")
    auth_b = await _auth(client, "inv-b")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(30)]}, headers=auth_a)
    await client.post("/api/v1/evidence/correlate", headers=auth_a)
    ev = (await client.get("/api/v1/evidence", headers=auth_a)).json()["items"][0]
    r = await client.post(f"/api/v1/evidence/{ev['id']}/investigate", headers=auth_b)
    assert r.status_code == 404  # RLS: not yours
