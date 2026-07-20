"""AI classifier end-to-end with a fake reasoning provider.

The LLM is faked (deterministic); everything else is real — the unclassified
event is selected, the proposal is validated against the seeded ATT&CK
catalog, a hallucinated id is dropped, and the mapping lands source='ai',
capped, quarantined from correlation scoring.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

import argus.services.ai_classifier as ai_classifier
from argus.domain.reasoning import ReasoningResponse
from argus.infrastructure.db.models import EventTechnique, MitreTechnique, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}
REAL_ID = "T1105"  # Ingress Tool Transfer — seeded below


@pytest.fixture
async def client(migrated_db):
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    async with admin_session() as s:
        await s.execute(delete(Tenant))
        # seed a minimal ATT&CK catalog (the loader script does this in real life)
        for tid, name, tac in [
            (REAL_ID, "Ingress Tool Transfer", ["command-and-control"]),
            ("T1059.001", "PowerShell", ["execution"]),
        ]:
            await s.execute(
                pg_insert(MitreTechnique)
                .values(technique_id=tid, name=name, tactics=tac, is_subtechnique="." in tid)
                .on_conflict_do_nothing()
            )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="ai") -> tuple[dict, str]:
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
    return {"Authorization": f"Bearer {r.json()['access_token']}"}, tid


# an event the deterministic rules do NOT classify -> the long tail
def _unclassified_event(minute: int) -> dict:
    return {
        "@timestamp": f"2020-08-07T14:{minute:02d}:00Z", "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "wks-ai",
        "Image": "C:\\Tools\\customtool.exe", "CommandLine": "customtool.exe --sync remote",
        "Message": "Process Create",
    }


class FakeReasoner:
    name = "ollama"

    def __init__(self, text: str):
        self._text = text

    async def complete(self, req):
        return ReasoningResponse(text=self._text, provider="ollama", model="fake")


async def test_ai_classifier_tags_long_tail_and_quarantines(client, monkeypatch):
    auth, tid = await _auth(client, "ai-tail")

    r = await client.post("/api/v1/events", json={
        "source": "securitydatasets",
        "events": [_unclassified_event(0), _unclassified_event(5)],
    }, headers=auth)
    assert r.json()["normalized"] == 2

    # rules classified nothing here -> no mappings yet
    async with tenant_session(uuid.UUID(tid)) as s:
        assert await s.scalar(select(EventTechnique.id).limit(1)) is None

    # model proposes a real id plus a hallucinated one that must be dropped
    fake_json = (
        f'[{{"technique_id":"{REAL_ID}","confidence":88,"rationale":"remote sync tool"}},'
        f'{{"technique_id":"T9999","confidence":95,"rationale":"hallucinated"}}]'
    )
    monkeypatch.setattr(
        ai_classifier, "get_reasoning_provider", lambda name: FakeReasoner(fake_json)
    )

    r = await client.post("/api/v1/mitre/ai-classify", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["signatures_examined"] == 1  # both events share one signature
    assert body["events_tagged"] == 2  # fanned out to the whole group
    assert [p["technique_id"] for p in body["proposals"]] == [REAL_ID]  # T9999 dropped
    assert body["proposals"][0]["confidence"] == 50  # capped

    # persisted as AI-sourced, capped; hallucination absent
    async with tenant_session(uuid.UUID(tid)) as s:
        rows = (await s.scalars(select(EventTechnique))).all()
        assert len(rows) == 2
        assert {r.technique_id for r in rows} == {REAL_ID}
        assert all(r.mapping_source == "ai" and r.confidence == 50 for r in rows)

    # visible in coverage, attributed to 'ai'
    cov = (await client.get("/api/v1/mitre/coverage", headers=auth)).json()
    assert cov["by_source"].get("ai", 0) == 2

    # quarantined: AI-only events do not build evidence by default
    assert (await client.post("/api/v1/evidence/correlate", headers=auth)).status_code == 200
    assert (await client.get("/api/v1/evidence", headers=auth)).json()["total"] == 0


async def test_ai_classify_noop_when_nothing_unclassified(client, monkeypatch):
    auth, _ = await _auth(client, "ai-empty")
    monkeypatch.setattr(
        ai_classifier, "get_reasoning_provider", lambda name: FakeReasoner("[]")
    )
    r = await client.post("/api/v1/mitre/ai-classify", headers=auth)
    assert r.status_code == 200
    assert r.json() == {
        "signatures_examined": 0, "events_tagged": 0,
        "techniques_written": 0, "proposals": [],
    }
