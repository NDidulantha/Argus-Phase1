"""Case workflow: create from evidence, status flow, notes, tenant isolation."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from argus.infrastructure.db.models import Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="cases") -> dict:
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


async def _make_evidence(client, auth) -> int:
    await client.post("/api/v1/events", json={"source": "securitydatasets",
        "events": [_lsass(30), _lsass(31)]}, headers=auth)
    await client.post("/api/v1/evidence/correlate", headers=auth)
    return (await client.get("/api/v1/evidence", headers=auth)).json()["items"][0]["id"]


async def test_case_lifecycle(client):
    auth = await _auth(client)
    evidence_id = await _make_evidence(client, auth)

    # create from evidence: severity derived from the evidence score
    r = await client.post(
        "/api/v1/cases",
        json={"title": "Credential access on WS5", "evidence_ids": [evidence_id]},
        headers=auth,
    )
    assert r.status_code == 201, r.text
    case = r.json()
    assert case["status"] == "new"
    assert case["assignee_email"] == "a@cases.x"
    assert case["evidence_count"] == 1
    assert case["evidence"][0]["id"] == evidence_id
    assert case["severity"] in {"critical", "high", "medium", "low"}

    # status flow + note
    r = await client.patch(
        f"/api/v1/cases/{case['id']}", json={"status": "investigating"}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["status"] == "investigating"

    r = await client.post(
        f"/api/v1/cases/{case['id']}/notes", json={"body": "Confirmed LSASS access."},
        headers=auth,
    )
    assert r.status_code == 201
    notes = r.json()["notes"]
    assert len(notes) == 1
    assert notes[0]["author_email"] == "a@cases.x"

    # attach is idempotent
    r = await client.post(
        f"/api/v1/cases/{case['id']}/evidence", json={"evidence_id": evidence_id}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["evidence_count"] == 1

    # list reflects the update
    r = await client.get("/api/v1/cases", headers=auth)
    assert r.json()["total"] == 1
    assert r.json()["items"][0]["status"] == "investigating"

    # status filter
    r = await client.get("/api/v1/cases", params={"status": "closed"}, headers=auth)
    assert r.json()["total"] == 0


async def test_invalid_status_rejected(client):
    auth = await _auth(client)
    r = await client.post("/api/v1/cases", json={"title": "t"}, headers=auth)
    case_id = r.json()["id"]
    r = await client.patch(f"/api/v1/cases/{case_id}", json={"status": "archived"}, headers=auth)
    assert r.status_code == 422


async def test_create_with_missing_evidence_404(client):
    auth = await _auth(client)
    r = await client.post(
        "/api/v1/cases", json={"title": "t", "evidence_ids": [999999]}, headers=auth
    )
    assert r.status_code == 404


async def test_cases_are_tenant_isolated(client):
    auth_a = await _auth(client, "case-a")
    auth_b = await _auth(client, "case-b")
    r = await client.post("/api/v1/cases", json={"title": "tenant A case"}, headers=auth_a)
    case_id = r.json()["id"]

    assert (await client.get("/api/v1/cases", headers=auth_b)).json()["total"] == 0
    assert (await client.get(f"/api/v1/cases/{case_id}", headers=auth_b)).status_code == 404
