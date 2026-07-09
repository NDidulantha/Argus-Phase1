"""RAG: evidence objects are embedded on correlate and retrievable by
similarity, tenant-scoped."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

from argus.infrastructure.db.models import MitreTechnique, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        for tid, name, tac in [
            ("T1003.001", "LSASS Memory", ["credential-access"]),
            ("T1059.001", "PowerShell", ["execution"]),
            ("T1087.001", "Account Discovery", ["discovery"]),
        ]:
            await s.execute(
                pg_insert(MitreTechnique)
                .values(technique_id=tid, name=name, tactics=tac, is_subtechnique="." in tid)
                .on_conflict_do_nothing()
            )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="rag") -> dict:
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


def _lsass(host, minute):
    return {"@timestamp": f"2020-08-07T{host[-1]}4:{minute:02d}:00Z", "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": host,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "Message": "Process accessed lsass.exe"}


async def test_correlate_embeds_and_similar_retrieves(client):
    auth = await _auth(client)
    # two credential-access hosts + one that's just powershell
    for h in ("HOSTA", "HOSTB"):
        await client.post("/api/v1/events", json={"source": "securitydatasets",
            "events": [_lsass(h, 30), _lsass(h, 31)]}, headers=auth)
    await client.post("/api/v1/events", json={"source": "wazuh", "events": [
        {"timestamp": "2020-08-07T20:00:00+0000",
         "rule": {"id": "1", "level": 5, "description": "ps", "groups": ["g"],
                  "mitre": {"id": ["T1087.001"]}}, "agent": {"name": "HOSTC"}}]}, headers=auth)

    r = await client.post("/api/v1/evidence/correlate?window_minutes=60", headers=auth)
    assert r.json()["evidence_objects_written"] >= 3

    ev = (await client.get("/api/v1/evidence", headers=auth)).json()["items"]
    # pick a credential-access object
    cred = next(e for e in ev if "T1003.001" in e["technique_ids"])

    sim = (await client.get(f"/api/v1/evidence/{cred['id']}/similar?k=3", headers=auth)).json()
    assert len(sim["similar"]) >= 1
    top = sim["similar"][0]
    # the most similar object should be the OTHER credential-access host,
    # not the discovery one
    assert "T1003.001" in top["technique_ids"]
    assert top["similarity"] >= sim["similar"][-1]["similarity"]


async def test_similar_is_tenant_scoped(client):
    auth_a = await _auth(client, "rag-a")
    auth_b = await _auth(client, "rag-b")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass("H", 30)]}, headers=auth_a)
    await client.post("/api/v1/evidence/correlate", headers=auth_a)
    ev = (await client.get("/api/v1/evidence", headers=auth_a)).json()["items"]
    # tenant B cannot see or query tenant A's evidence
    r = await client.get(f"/api/v1/evidence/{ev[0]['id']}/similar", headers=auth_b)
    assert r.status_code == 404
