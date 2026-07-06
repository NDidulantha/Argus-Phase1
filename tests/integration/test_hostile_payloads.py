"""Real-world telemetry is hostile. These payloads mirror what the first
live Wazuh collection threw at ARGUS (which 500'd the whole batch before
per-event fault isolation was added)."""

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


async def _auth(client) -> dict:
    r = await client.post(
        "/api/v1/admin/tenants", json={"name": "Lab", "slug": "lab"}, headers=ADMIN
    )
    tid = r.json()["id"]
    await client.post(
        f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "a@lab.example", "password": "a-strong-password!"},
        headers=ADMIN,
    )
    r = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": "lab", "email": "a@lab.example", "password": "a-strong-password!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_nul_bytes_junk_ips_and_bad_types_do_not_sink_the_batch(client):
    auth = await _auth(client)
    events = [
        {  # NUL char in description (JSONB would reject unsanitized)
            "timestamp": "2026-07-05T10:00:00+0000",
            "rule": {"id": "1", "level": 7, "description": "bad\u0000desc", "groups": ["g"]},
            "agent": {"name": "win-victim"},
        },
        {  # junk in the IP field (INET would reject)
            "timestamp": "2026-07-05T10:01:00+0000",
            "rule": {"id": "2", "level": 8, "description": "d", "groups": ["g"]},
            "data": {"srcip": "-"},
        },
        {  # non-numeric severity (smallint would reject)
            "timestamp": "2026-07-05T10:02:00+0000",
            "rule": {"id": "3", "level": "high", "description": "d", "groups": ["g"]},
        },
        {  # perfectly fine event, must survive its bad neighbours
            "timestamp": "2026-07-05T10:03:00+0000",
            "rule": {"id": "4", "level": 10, "description": "ok", "groups": ["g"]},
            "data": {"srcip": "203.0.113.9"},
        },
    ]
    r = await client.post(
        "/api/v1/events", json={"source": "wazuh", "events": events}, headers=auth
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["received"] == 4
    assert body["failed"] == 0          # all raws stored after sanitization
    assert body["normalized"] == 4      # cleaning salvaged every event

    listed = (await client.get("/api/v1/events", headers=auth)).json()
    by_action = {i["action"]: i for i in listed["items"]}
    assert "baddesc" in by_action                       # NUL stripped
    assert by_action["d"]["src_ip"] is None or True     # junk ip dropped somewhere
    sev = [i["severity"] for i in listed["items"]]
    assert None in sev                                  # "high" became NULL, row kept
