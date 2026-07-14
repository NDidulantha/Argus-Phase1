"""Evidence graph built on ingest; attack chain reconstructed via API."""

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


async def _auth(client, slug="graph") -> dict:
    r = await client.post("/api/v1/admin/tenants", json={"name": slug, "slug": slug}, headers=ADMIN)
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": f"a@{slug}.x", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": slug, "email": f"a@{slug}.x", "password": "a-strong-password!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _sysmon(image, parent=None, target=None, ts="2020-08-07T14:35:00Z", host="WS5"):
    attrs = {
        "EventID": 10,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": host,
        "Image": image,
    }
    if parent:
        attrs["ParentImage"] = parent
    if target:
        attrs["TargetImage"] = target
    attrs["@timestamp"] = ts
    return attrs


async def test_graph_reconstructs_mimikatz_chain(client):
    auth = await _auth(client)
    events = [
        _sysmon("C:\\Windows\\explorer.exe", parent="C:\\Windows\\System32\\services.exe"),
        _sysmon("C:\\Windows\\System32\\powershell.exe", parent="C:\\Windows\\explorer.exe"),
        _sysmon("C:\\Windows\\System32\\powershell.exe", target="C:\\Windows\\System32\\lsass.exe"),
    ]
    r = await client.post(
        "/api/v1/events", json={"source": "securitydatasets", "events": events}, headers=auth
    )
    assert r.json()["normalized"] == 3

    # find the services.exe process entity (root of the chain)
    ents = (
        await client.get("/api/v1/graph/entities?entity_type=process&search=services", headers=auth)
    ).json()
    services_id = ents["items"][0]["id"]

    chain = (
        await client.get(f"/api/v1/graph/entities/{services_id}/chain?max_depth=4", headers=auth)
    ).json()
    keys_at_depth = {(c["depth"], c["entity_key"]) for c in chain["chain"]}
    # services -> explorer -> powershell -> lsass, reconstructed by traversal
    assert (0, "services.exe") in keys_at_depth
    assert (1, "explorer.exe") in keys_at_depth
    assert (2, "powershell.exe") in keys_at_depth
    assert (3, "lsass.exe") in keys_at_depth


async def test_neighborhood_and_tenant_scope(client):
    auth_a = await _auth(client, "graph-a")
    auth_b = await _auth(client, "graph-b")
    await client.post(
        "/api/v1/events",
        json={
            "source": "securitydatasets",
            "events": [_sysmon("C:\\x\\powershell.exe", target="C:\\y\\lsass.exe")],
        },
        headers=auth_a,
    )
    ents = (await client.get("/api/v1/graph/entities?search=powershell", headers=auth_a)).json()
    pid = ents["items"][0]["id"]
    nb = (await client.get(f"/api/v1/graph/entities/{pid}/neighborhood", headers=auth_a)).json()
    assert any(e["relation"] == "accessed" for e in nb["edges"])

    # tenant B sees no entities
    assert (await client.get("/api/v1/graph/entities", headers=auth_b)).json()["total"] == 0


async def test_graph_overview_returns_entities_and_edges(client):
    auth = await _auth(client, "graph-ov")
    await client.post(
        "/api/v1/events",
        json={
            "source": "securitydatasets",
            "events": [_sysmon("C:\\x\\powershell.exe", target="C:\\y\\lsass.exe")],
        },
        headers=auth,
    )
    ov = (await client.get("/api/v1/graph/overview", headers=auth)).json()
    assert ov["total_entities"] >= 2
    keys = {e["entity_key"] for e in ov["entities"]}
    assert {"powershell.exe", "lsass.exe"} <= keys
    ids = {e["id"] for e in ov["entities"]}
    # every edge's endpoints are in the returned entity set
    assert all(
        e["src_entity_id"] in ids and e["dst_entity_id"] in ids for e in ov["edges"]
    )
    assert any(e["relation"] == "accessed" for e in ov["edges"])
