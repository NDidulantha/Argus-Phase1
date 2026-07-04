"""End-to-end auth flow against a real Postgres: provision -> login -> use."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from argus.infrastructure.db.models import Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:  # clean slate for each test
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _provision(client) -> str:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "Bank A", "slug": "bank-a"}, headers=ADMIN
    )
    assert r.status_code == 201, r.text
    tenant_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/admin/tenants/{tenant_id}/users",
        json={
            "email": "analyst@bank-a.example",
            "password": "a-strong-password!",
            "role": "analyst",
        },
        headers=ADMIN,
    )
    assert r.status_code == 201, r.text
    return tenant_id


async def test_full_login_flow(client):
    tenant_id = await _provision(client)

    r = await client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "bank-a",
            "email": "analyst@bank-a.example",
            "password": "a-strong-password!",
        },
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    r = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["tenant_id"] == tenant_id
    assert r.json()["role"] == "analyst"


async def test_wrong_password_and_unknown_user_are_indistinguishable(client):
    await _provision(client)
    bad_pw = await client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "bank-a",
            "email": "analyst@bank-a.example",
            "password": "wrong-password!!",
        },
    )
    no_user = await client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "bank-a",
            "email": "ghost@bank-a.example",
            "password": "wrong-password!!",
        },
    )
    assert bad_pw.status_code == no_user.status_code == 401
    assert bad_pw.json() == no_user.json()  # identical body: no user enumeration


async def test_protected_endpoint_requires_token(client):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401


async def test_admin_endpoints_require_admin_key(client):
    r = await client.post(
        "/api/v1/admin/tenants",
        json={"name": "X", "slug": "x"},
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert r.status_code == 401
