"""Alert triage: status changes, status filter, dismissed clusters staying
dismissed across correlation reruns, and auto-correlation after ingest."""

import asyncio

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

from argus.core.config import get_settings
from argus.infrastructure.db.models import MitreTechnique, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        await s.execute(
            pg_insert(MitreTechnique)
            .values(
                technique_id="T1003.001",
                name="LSASS Memory",
                tactics=["credential-access"],
                is_subtechnique=True,
            )
            .on_conflict_do_nothing()
        )
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug) -> dict:
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


async def _seed_evidence(client, auth, host="wks-1"):
    r = await client.post(
        "/api/v1/events",
        json={"source": "securitydatasets", "events": [_lsass(host, m) for m in (0, 5)]},
        headers=auth,
    )
    assert r.status_code == 202
    r = await client.post("/api/v1/evidence/correlate", headers=auth)
    assert r.status_code == 200
    r = await client.get("/api/v1/evidence", headers=auth)
    return r.json()["items"]


async def test_triage_status_change_and_filter(client):
    auth = await _auth(client, "triage")
    items = await _seed_evidence(client, auth)
    assert len(items) == 1 and items[0]["status"] == "open"
    eid = items[0]["id"]

    r = await client.patch(
        f"/api/v1/evidence/{eid}", json={"status": "acknowledged"}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"

    r = await client.get("/api/v1/evidence", params={"status": "open"}, headers=auth)
    assert r.json()["total"] == 0
    r = await client.get("/api/v1/evidence", params={"status": "acknowledged"}, headers=auth)
    assert r.json()["total"] == 1


async def test_triage_rejects_unknown_status(client):
    auth = await _auth(client, "triage-bad")
    items = await _seed_evidence(client, auth)
    r = await client.patch(
        f"/api/v1/evidence/{items[0]['id']}", json={"status": "closed"}, headers=auth
    )
    assert r.status_code == 422


async def test_triage_404_for_missing_object(client):
    auth = await _auth(client, "triage-404")
    r = await client.patch("/api/v1/evidence/99999", json={"status": "dismissed"}, headers=auth)
    assert r.status_code == 404


async def test_dismissed_cluster_not_resurrected_by_rerun(client):
    auth = await _auth(client, "triage-dismiss")
    items = await _seed_evidence(client, auth)
    eid = items[0]["id"]
    await client.patch(f"/api/v1/evidence/{eid}", json={"status": "dismissed"}, headers=auth)

    r = await client.post("/api/v1/evidence/correlate", headers=auth)
    assert r.status_code == 200
    r = await client.get("/api/v1/evidence", headers=auth)
    items = r.json()["items"]
    # still exactly one object: the dismissed one, no fresh open duplicate
    assert [i["status"] for i in items] == ["dismissed"]
    assert items[0]["id"] == eid


async def test_auto_correlation_runs_after_ingest(client):
    auth = await _auth(client, "auto-corr")
    settings = get_settings()
    original = settings.auto_correlate_debounce_seconds
    settings.auto_correlate_debounce_seconds = 0.05
    try:
        r = await client.post(
            "/api/v1/events",
            json={"source": "securitydatasets", "events": [_lsass("wks-9", m) for m in (0, 5)]},
            headers=auth,
        )
        assert r.status_code == 202

        # no manual correlate: the debounced background task builds evidence
        for _ in range(40):
            await asyncio.sleep(0.05)
            r = await client.get("/api/v1/evidence", headers=auth)
            if r.json()["total"]:
                break
        assert r.json()["total"] == 1
        assert r.json()["items"][0]["status"] == "open"
    finally:
        settings.auto_correlate_debounce_seconds = original
