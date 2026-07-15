"""Reasoning agent flow with a FAKE provider (no Ollama needed in CI):
evidence -> curated context -> narrative, tenant-scoped."""

import json

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


async def test_investigation_persisted_with_stage_trail(client):
    auth = await _auth(client, "inv-hist")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(30), _lsass(31)]}, headers=auth)
    await client.post("/api/v1/evidence/correlate", headers=auth)
    ev = (await client.get("/api/v1/evidence", headers=auth)).json()["items"][0]

    r = await client.post(f"/api/v1/evidence/{ev['id']}/investigate", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["investigation_id"] > 0
    assert [s["stage"] for s in body["stages"]] == ["scope", "collect", "conclude", "ground"]

    # the run survives as an auditable record
    r = await client.get(f"/api/v1/evidence/{ev['id']}/investigations", headers=auth)
    runs = r.json()
    assert len(runs) == 1
    assert runs[0]["status"] == "complete"
    assert runs[0]["narrative"] == body["narrative"]
    assert runs[0]["grounded"] is False  # fake provider fabricates mimikatz
    assert runs[0]["duration_ms"] is not None


async def test_directives_steer_the_prompt(client, monkeypatch):
    captured = {}

    class CapturingProvider:
        name = "fake"

        async def complete(self, req):
            captured["prompt"] = req.prompt
            return ReasoningResponse(text="SUMMARY: nothing notable.", provider="fake",
                                     model="fake-1")

    monkeypatch.setattr(
        investigation_service, "get_reasoning_provider", lambda name=None: CapturingProvider()
    )
    auth = await _auth(client, "inv-steer")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(40)]}, headers=auth)
    await client.post("/api/v1/evidence/correlate", headers=auth)
    ev = (await client.get("/api/v1/evidence", headers=auth)).json()["items"][0]

    r = await client.post(
        f"/api/v1/evidence/{ev['id']}/investigate",
        json={"directives": ["focus on lateral movement", "rule out backup jobs"]},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    assert "ANALYST DIRECTIVES" in captured["prompt"]
    assert "focus on lateral movement" in captured["prompt"]
    assert r.json()["directives"] == ["focus on lateral movement", "rule out backup jobs"]


async def test_investigate_stream_emits_staged_events(client):
    auth = await _auth(client, "inv-sse")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(50)]}, headers=auth)
    await client.post("/api/v1/evidence/correlate", headers=auth)
    ev = (await client.get("/api/v1/evidence", headers=auth)).json()["items"][0]

    events = []
    async with client.stream(
        "POST", f"/api/v1/evidence/{ev['id']}/investigate/stream", headers=auth
    ) as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        async for line in r.aiter_lines():
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))

    kinds = [(e["type"], e.get("stage")) for e in events]
    assert kinds[:4] == [("stage", "scope"), ("stage", "collect"),
                         ("stage", "conclude"), ("stage", "ground")]
    assert events[-1]["type"] == "complete"
    assert events[-1]["investigation"]["status"] == "complete"
    # stage timestamps are the provenance trail: causally ordered
    ats = [e["at"] for e in events if e["type"] == "stage"]
    assert ats == sorted(ats)
