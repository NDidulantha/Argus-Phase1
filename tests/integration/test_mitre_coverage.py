"""ATT&CK linking on ingest + per-tenant coverage, against real Postgres."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert

from argus.infrastructure.db.models import MitreTechnique, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


def _alert(rule_id, level, host, minute, techniques):
    return {
        "timestamp": f"2026-07-06T10:{minute:02d}:00+0000",
        "rule": {
            "id": rule_id,
            "level": level,
            "description": "d",
            "groups": ["g"],
            "mitre": {"id": techniques},
        },
        "agent": {"name": host},
    }


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        # seed a minimal catalog (loader script does this in real life)
        for tid, name, tac in [
            ("T1110", "Brute Force", ["credential-access"]),
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


async def _auth(client, slug="mitre-a") -> dict:
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


async def test_ingest_links_techniques_and_coverage_reports(client):
    auth = await _auth(client)
    events = [
        _alert("60204", 10, "win10", 1, ["T1110"]),
        _alert("60204", 10, "win10", 2, ["T1110"]),
        _alert("91802", 8, "win10", 3, ["T1059.001"]),
    ]
    await client.post("/api/v1/events", json={"source": "wazuh", "events": events}, headers=auth)

    r = await client.get("/api/v1/mitre/coverage", headers=auth)
    body = r.json()
    assert body["techniques_seen"] == 2
    assert body["total_events"] == 3
    top = body["coverage"][0]
    assert top["technique_id"] == "T1110"
    assert top["event_count"] == 2
    assert top["name"] == "Brute Force"
    assert top["tactics"] == ["credential-access"]
    assert top["sources"] == {"vendor": 2}  # vendor IDs present -> vendor source
    assert body["by_source"]["vendor"] == 3


async def test_technique_catalog_lookup(client):
    auth = await _auth(client, "mitre-b")
    r = await client.get("/api/v1/mitre/techniques/t1110", headers=auth)  # lowercase ok
    assert r.status_code == 200
    assert r.json()["name"] == "Brute Force"
    r = await client.get("/api/v1/mitre/techniques/T9999", headers=auth)
    assert r.status_code == 404


async def test_coverage_is_tenant_scoped(client):
    auth_a = await _auth(client, "mitre-c")
    auth_b = await _auth(client, "mitre-d")
    await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [_alert("60204", 10, "h", 1, ["T1110"])]},
        headers=auth_a,
    )
    r = await client.get("/api/v1/mitre/coverage", headers=auth_b)
    assert r.json()["techniques_seen"] == 0


async def test_matrix_returns_full_catalog(client):
    auth = await _auth(client)
    r = await client.get("/api/v1/mitre/matrix", headers=auth)
    assert r.status_code == 200
    items = r.json()
    # catalog fixtures inserted by this module's client fixture
    ids = {t["technique_id"] for t in items}
    assert len(ids) == len(items)  # unique
    assert all({"technique_id", "name", "tactics", "is_subtechnique"} <= set(t) for t in items)
