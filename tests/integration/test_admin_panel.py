"""MSSP control plane: tenant listing with stats, tenant/user management."""

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


async def test_admin_endpoints_require_the_key(client):
    for method, path in [
        ("GET", "/api/v1/admin/tenants"),
        ("PATCH", "/api/v1/admin/tenants/00000000-0000-0000-0000-000000000000"),
    ]:
        r = await client.request(method, path, headers={"X-Admin-Key": "wrong"})
        assert r.status_code == 401
        r = await client.request(method, path)
        assert r.status_code == 401


async def test_list_tenants_with_stats(client):
    r = await client.post(
        "/api/v1/admin/tenants",
        json={"name": "Acme Bank", "slug": "acme", "sector": "finance"},
        headers=ADMIN,
    )
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["sector"] == "finance"
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "a@acme.io", "password": "a-strong-password!"},
        headers=ADMIN,
    )

    r = await client.get("/api/v1/admin/tenants", headers=ADMIN)
    assert r.status_code == 200
    rows = {t["slug"]: t for t in r.json()}
    assert rows["acme"]["user_count"] == 1
    assert rows["acme"]["event_count"] == 0
    assert rows["acme"]["open_alerts"] == 0
    assert rows["acme"]["sector"] == "finance"


async def test_update_tenant_and_deactivation_blocks_login(client):
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "Beta Corp", "slug": "beta"}, headers=ADMIN
    )
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "b@beta.io", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    login = {"tenant_slug": "beta", "email": "b@beta.io", "password": "a-strong-password!"}
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 200

    r = await client.patch(
        f"/api/v1/admin/tenants/{tid}",
        json={"sector": "healthcare", "is_active": False},
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert r.json()["sector"] == "healthcare"
    assert r.json()["is_active"] is False

    # deactivated tenant: logins are refused with the generic 401
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 401

    r = await client.patch(f"/api/v1/admin/tenants/{tid}", json={"is_active": True}, headers=ADMIN)
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 200


async def test_manage_tenant_users(client):
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "Gamma", "slug": "gamma"}, headers=ADMIN
    )
    tid = r.json()["id"]
    r = await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "u1@gamma.io", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    uid = r.json()["id"]

    r = await client.get(f"/api/v1/admin/tenants/{tid}/users", headers=ADMIN)
    assert r.status_code == 200
    assert [(u["email"], u["role"], u["is_active"]) for u in r.json()] == [
        ("u1@gamma.io", "analyst", True)
    ]

    # promote + deactivate
    r = await client.patch(
        f"/api/v1/admin/tenants/{tid}/users/{uid}",
        json={"role": "admin", "is_active": False},
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    assert r.json()["is_active"] is False

    login = {"tenant_slug": "gamma", "email": "u1@gamma.io", "password": "a-strong-password!"}
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 401

    # reactivate with a password reset
    r = await client.patch(
        f"/api/v1/admin/tenants/{tid}/users/{uid}",
        json={"is_active": True, "password": "another-strong-pass!"},
        headers=ADMIN,
    )
    assert r.status_code == 200
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 401
    login["password"] = "another-strong-pass!"
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 200


async def test_user_routes_404_on_unknown_tenant_or_user(client):
    ghost = "00000000-0000-0000-0000-000000000000"
    r = await client.get(f"/api/v1/admin/tenants/{ghost}/users", headers=ADMIN)
    assert r.status_code == 404

    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "Delta", "slug": "delta"}, headers=ADMIN
    )
    tid = r.json()["id"]
    r = await client.patch(
        f"/api/v1/admin/tenants/{tid}/users/{ghost}", json={"role": "admin"}, headers=ADMIN
    )
    assert r.status_code == 404
