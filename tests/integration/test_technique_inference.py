"""Rule-based inference lights up events that have NO vendor ATT&CK IDs
(the Mordor/Sysmon case)."""

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
        ]:
            await s.execute(
                pg_insert(MitreTechnique)
                .values(technique_id=tid, name=name, tactics=tac, is_subtechnique="." in tid)
                .on_conflict_do_nothing()
            )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="infer") -> dict:
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


# A Mordor-style Sysmon event: NO mitre ids, just raw fields.
LSASS_ACCESS = {
    "@timestamp": "2020-08-07T14:35:00Z",
    "EventID": 10,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "Hostname": "WORKSTATION5",
    "Message": "Process accessed:\nTargetImage: C:\\Windows\\System32\\lsass.exe",
}


async def test_lsass_event_gets_rule_inferred_technique(client):
    auth = await _auth(client)
    r = await client.post(
        "/api/v1/events",
        json={"source": "securitydatasets", "events": [LSASS_ACCESS]},
        headers=auth,
    )
    assert r.json()["normalized"] == 1

    cov = (await client.get("/api/v1/mitre/coverage", headers=auth)).json()
    assert cov["techniques_seen"] >= 1
    t1003 = next(c for c in cov["coverage"] if c["technique_id"] == "T1003.001")
    assert t1003["sources"] == {"rules": 1}  # inferred, not vendor
    assert t1003["max_confidence"] == 90
    assert cov["by_source"] == {"rules": 1}
