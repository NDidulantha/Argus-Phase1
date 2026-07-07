"""Correlation builds scored evidence objects from ingested attack activity."""

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
            ("T1021.002", "SMB/Admin Shares", ["lateral-movement"]),
        ]:
            await s.execute(
                pg_insert(MitreTechnique)
                .values(technique_id=tid, name=name, tactics=tac, is_subtechnique="." in tid)
                .on_conflict_do_nothing()
            )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="corr") -> dict:
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
    return {"@timestamp": f"2020-08-07T14:{minute:02d}:00Z", "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": host,
            "Message": "Process accessed: C:\\Windows\\System32\\lsass.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe"}


def _wazuh_smb(host, minute):
    return {"timestamp": f"2020-08-07T14:{minute:02d}:00+0000",
            "rule": {"id": "1", "level": 10, "description": "psexec",
                     "groups": ["g"], "mitre": {"id": ["T1021.002"]}},
            "agent": {"name": host}}


async def test_correlation_builds_scored_objects(client):
    auth = await _auth(client)
    # host A: credential dumping + lateral movement in one window = high score
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass("HOSTA", 30), _lsass("HOSTA", 31)]}, headers=auth)
    await client.post("/api/v1/events", json={"source": "wazuh",
        "events": [_wazuh_smb("HOSTA", 32)]}, headers=auth)

    r = await client.post("/api/v1/evidence/correlate?window_minutes=30", headers=auth)
    assert r.json()["evidence_objects_written"] >= 1

    lst = (await client.get("/api/v1/evidence?min_score=0", headers=auth)).json()
    assert lst["total"] >= 1
    top = lst["items"][0]
    assert top["host_name"] == "HOSTA"
    assert set(top["technique_ids"]) >= {"T1003.001", "T1021.002"}
    assert "credential-access" in top["tactics"] and "lateral-movement" in top["tactics"]
    assert top["score"] > 50  # critical tactics present

    detail = (await client.get(f"/api/v1/evidence/{top['id']}", headers=auth)).json()
    assert detail["score_breakdown"]["critical_tactic_bonus"] == 20
    assert any(t["technique_id"] == "T1003.001" for t in detail["techniques"])


async def test_correlation_is_idempotent(client):
    auth = await _auth(client, "corr2")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass("H", 30)]}, headers=auth)
    r1 = await client.post("/api/v1/evidence/correlate", headers=auth)
    r2 = await client.post("/api/v1/evidence/correlate", headers=auth)
    assert r1.json() == r2.json()  # rerun replaces, does not duplicate
    lst = (await client.get("/api/v1/evidence", headers=auth)).json()
    assert lst["total"] == r2.json()["evidence_objects_written"]


async def test_evidence_tenant_scoped(client):
    auth_a = await _auth(client, "corr-a")
    auth_b = await _auth(client, "corr-b")
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass("H", 30)]}, headers=auth_a)
    await client.post("/api/v1/evidence/correlate", headers=auth_a)
    assert (await client.get("/api/v1/evidence", headers=auth_b)).json()["total"] == 0
