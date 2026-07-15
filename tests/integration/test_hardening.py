"""Phase-2 hardening: TOTP MFA login step, credential encryption at rest,
self-service ingest tokens."""

import time

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from argus.core.security import _totp_code
from argus.infrastructure.db.models import Connector, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug):
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
    return tid, {"Authorization": f"Bearer {r.json()['access_token']}"}


def _code(secret: str) -> str:
    return _totp_code(secret, int(time.time() // 30))


async def test_mfa_full_lifecycle(client):
    _, auth = await _auth(client, "mfa")
    login = {"tenant_slug": "mfa", "email": "a@mfa.x", "password": "a-strong-password!"}

    r = await client.get("/api/v1/auth/mfa", headers=auth)
    assert r.json() == {"enabled": False, "pending": False}

    r = await client.post("/api/v1/auth/mfa/enrol", headers=auth)
    assert r.status_code == 200
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/")
    assert (await client.get("/api/v1/auth/mfa", headers=auth)).json()["pending"] is True

    # enrolled but not activated: login still passes without a code
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 200

    r = await client.post("/api/v1/auth/mfa/activate", json={"code": "000000"}, headers=auth)
    assert r.status_code == 403
    r = await client.post("/api/v1/auth/mfa/activate", json={"code": _code(secret)}, headers=auth)
    assert r.status_code == 204
    assert (await client.get("/api/v1/auth/mfa", headers=auth)).json()["enabled"] is True

    # password alone now yields the mfa_required challenge
    r = await client.post("/api/v1/auth/login", json=login)
    assert r.status_code == 401
    assert r.json()["detail"] == "mfa_required"
    # wrong code -> generic invalid
    r = await client.post("/api/v1/auth/login", json={**login, "otp_code": "000000"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"
    # right code -> in
    r = await client.post("/api/v1/auth/login", json={**login, "otp_code": _code(secret)})
    assert r.status_code == 200

    # wrong password + valid-format code stays generic (no mfa hint leaks)
    r = await client.post(
        "/api/v1/auth/login", json={**login, "password": "wrong-password!!"}
    )
    assert r.json()["detail"] == "Invalid credentials"

    # disable needs a live code
    r = await client.post("/api/v1/auth/mfa/disable", json={"code": "000000"}, headers=auth)
    assert r.status_code == 403
    r = await client.post("/api/v1/auth/mfa/disable", json={"code": _code(secret)}, headers=auth)
    assert r.status_code == 204
    assert (await client.post("/api/v1/auth/login", json=login)).status_code == 200


async def test_connector_credentials_encrypted_at_rest(client):
    tid, auth = await _auth(client, "sealcreds")
    r = await client.post(
        "/api/v1/connectors",
        json={
            "vendor": "wazuh",
            "name": "lab",
            "endpoint_url": "https://indexer.example:9200",
            "credentials": {"username": "svc", "password": "hunter2-super-secret"},
        },
        headers=auth,
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    assert "credentials" not in r.json()  # never in API responses

    import uuid as _uuid

    async with tenant_session(_uuid.UUID(tid)) as s:
        stored = (await s.scalar(select(Connector).where(Connector.id == cid))).credentials
    assert set(stored) == {"__fernet__"}
    assert "hunter2-super-secret" not in str(stored)

    # update path re-seals replacement credentials too
    r = await client.patch(
        f"/api/v1/connectors/{cid}",
        json={"credentials": {"username": "svc", "password": "rotated-secret-9"}},
        headers=auth,
    )
    assert r.status_code == 200
    async with tenant_session(_uuid.UUID(tid)) as s:
        stored = (await s.scalar(select(Connector).where(Connector.id == cid))).credentials
    assert set(stored) == {"__fernet__"} and "rotated-secret-9" not in str(stored)


async def test_ingest_token_mints_and_ingests(client):
    _, auth = await _auth(client, "minter")
    r = await client.post("/api/v1/auth/ingest-token", json={"days": 30}, headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["expires_days"] == 30
    assert body["role"] == "analyst"

    machine = {"Authorization": f"Bearer {body['token']}"}
    r = await client.post(
        "/api/v1/events",
        json={"source": "wazuh", "events": [{"timestamp": "2020-08-07T14:00:00+0000",
              "rule": {"id": "1", "level": 3, "description": "ok", "groups": ["g"]},
              "agent": {"name": "h"}}]},
        headers=machine,
    )
    assert r.status_code == 202
    assert r.json()["received"] == 1

    r = await client.post("/api/v1/auth/ingest-token", json={"days": 999}, headers=auth)
    assert r.status_code == 422  # capped at 365
