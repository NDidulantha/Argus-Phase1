"""Connector config workflow: catalog, wizard test, health transitions,
credential write-only handling, tenant isolation."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

import argus.api.v1.endpoints.connectors as connectors_ep
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


async def _auth(client, slug="conn") -> dict:
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


WAZUH_DRAFT = {
    "vendor": "wazuh",
    "name": "Lab Wazuh",
    "endpoint_url": "https://127.0.0.1:59999",
    "credentials": {"username": "admin", "password": "secret"},
    "verify_tls": False,
}


async def test_catalog_lists_supported_and_planned(client):
    auth = await _auth(client, "conn-cat")
    catalog = (await client.get("/api/v1/connectors/catalog", headers=auth)).json()
    by_vendor = {c["vendor"]: c for c in catalog}
    assert by_vendor["wazuh"]["supported"] is True
    assert by_vendor["wazuh"]["default_mapping"]
    assert by_vendor["crowdstrike"]["supported"] is False


async def test_wizard_draft_test_fails_cleanly_when_unreachable(client):
    auth = await _auth(client, "conn-draft")
    r = await client.post(
        "/api/v1/connectors/test",
        json={k: WAZUH_DRAFT[k] for k in ("vendor", "endpoint_url", "credentials", "verify_tls")},
        headers=auth,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "reach" in body["detail"]


async def test_connector_lifecycle_and_health(client, monkeypatch):
    auth = await _auth(client, "conn-life")

    r = await client.post("/api/v1/connectors", json=WAZUH_DRAFT, headers=auth)
    assert r.status_code == 201, r.text
    conn = r.json()
    assert conn["status"] == "unconfigured"
    assert "credentials" not in conn  # write-only
    assert conn["field_mapping"]  # wazuh default mapping applied

    # stored test against the unreachable endpoint -> error status persisted
    r = await client.post(f"/api/v1/connectors/{conn['id']}/test", headers=auth)
    assert r.json()["status"] == "error"
    assert r.json()["last_error"]

    # a passing probe flips it to healthy
    async def fake_probe(vendor, endpoint_url, credentials, verify_tls):
        return True, "cluster 'lab' is green"

    monkeypatch.setattr(connectors_ep, "probe_connector", fake_probe)
    r = await client.post(f"/api/v1/connectors/{conn['id']}/test", headers=auth)
    assert r.json()["status"] == "healthy"
    assert r.json()["last_error"] is None

    r = await client.delete(f"/api/v1/connectors/{conn['id']}", headers=auth)
    assert r.status_code == 204
    assert (await client.get("/api/v1/connectors", headers=auth)).json()["items"] == []


async def test_unsupported_vendor_rejected(client):
    auth = await _auth(client, "conn-bad")
    r = await client.post(
        "/api/v1/connectors", json={**WAZUH_DRAFT, "vendor": "crowdstrike"}, headers=auth
    )
    assert r.status_code == 400


async def test_connectors_tenant_isolated(client):
    auth_a = await _auth(client, "conn-a")
    auth_b = await _auth(client, "conn-b")
    await client.post("/api/v1/connectors", json=WAZUH_DRAFT, headers=auth_a)
    assert (await client.get("/api/v1/connectors", headers=auth_b)).json()["items"] == []
