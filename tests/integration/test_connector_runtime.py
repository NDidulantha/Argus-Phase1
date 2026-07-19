"""Connector runtime: poll -> ingest -> advance cursor, with a fake collector.

The collector's network call is faked (get_collector monkeypatched); the rest
is real — the pulled Wazuh alerts go through the normal ingest path and land
as normalized events, and the connector's cursor / health advance.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, func, select

import argus.services.connector_runtime as runtime
from argus.connectors.collectors import CollectResult
from argus.infrastructure.db.models import Connector, NormalizedEvent, Tenant
from argus.infrastructure.db.session import admin_session, tenant_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}

WAZUH_DRAFT = {
    "vendor": "wazuh",
    "name": "Lab Wazuh",
    "endpoint_url": "https://127.0.0.1:59999",
    "credentials": {"username": "admin", "password": "secret"},
    "verify_tls": False,
}


@pytest.fixture
async def client(migrated_db):
    async with admin_session() as s:
        await s.execute(delete(Tenant))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client, slug="cr") -> tuple[dict, str]:
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
    return {"Authorization": f"Bearer {r.json()['access_token']}"}, tid


def _alert(ts: str, srcip: str = "8.8.8.8") -> dict:
    return {
        "@timestamp": ts,
        "timestamp": ts,
        "rule": {"id": "5710", "description": "sshd auth failed", "level": 5,
                 "groups": ["authentication_failed"]},
        "agent": {"name": "web01"},
        "data": {"srcip": srcip},
    }


class FakeCollector:
    def __init__(self, payloads, cursor, source="wazuh"):
        self.source = source
        self._payloads = payloads
        self._cursor = cursor
        self.seen_cursor = "unset"

    async def collect(self, connector, cursor, since, *, limit):
        self.seen_cursor = cursor
        return CollectResult(payloads=self._payloads, cursor=self._cursor)


CROWDSTRIKE_DRAFT = {
    "vendor": "crowdstrike",
    "name": "Lab Falcon",
    "endpoint_url": "https://api.crowdstrike.test",
    "credentials": {"client_id": "cid", "client_secret": "sec"},
    "verify_tls": True,
}


def _falcon_alert(ts: str) -> dict:
    return {
        "composite_id": f"ldt:{ts}",
        "timestamp": ts,
        "severity": 70,
        "tactic": "Defense Evasion",
        "technique_id": "T1036",
        "description": "masquerading as a system binary",
        "device": {"hostname": "WIN-01", "external_ip": "203.0.113.5"},
        "user_name": "jdoe",
        "filename": "svch0st.exe",
        "cmdline": "svch0st.exe -x",
    }


async def test_poll_ingests_alerts_and_advances_cursor(client, monkeypatch):
    auth, tid = await _auth(client, "cr-poll")
    r = await client.post("/api/v1/connectors", json=WAZUH_DRAFT, headers=auth)
    assert r.status_code == 201, r.text
    assert r.json()["enabled"] is True
    cid = r.json()["id"]

    alerts = [_alert("2026-07-19T10:00:01+00:00"), _alert("2026-07-19T10:00:02+00:00", "1.2.3.4")]
    monkeypatch.setattr(
        runtime, "get_collector",
        lambda vendor, creds: FakeCollector(alerts, "2026-07-19T10:00:02+00:00"),
    )

    r = await client.post(f"/api/v1/connectors/{cid}/poll", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "healthy"
    assert body["last_ingested"] == 2
    assert body["last_run_at"] is not None
    assert body["last_error"] is None

    # the alerts really landed as normalized events, and the cursor advanced
    async with tenant_session(uuid.UUID(tid)) as s:
        n = await s.scalar(select(func.count(NormalizedEvent.id)))
        assert n == 2
        cursor = await s.scalar(select(Connector.cursor).where(Connector.id == cid))
        assert cursor == "2026-07-19T10:00:02+00:00"


async def test_second_poll_resumes_from_cursor(client, monkeypatch):
    auth, tid = await _auth(client, "cr-resume")
    cid = (await client.post("/api/v1/connectors", json=WAZUH_DRAFT, headers=auth)).json()["id"]

    first = FakeCollector([_alert("2026-07-19T10:00:01+00:00")], "2026-07-19T10:00:01+00:00")
    monkeypatch.setattr(runtime, "get_collector", lambda v, c: first)
    await client.post(f"/api/v1/connectors/{cid}/poll", headers=auth)
    assert first.seen_cursor is None  # first run has no cursor

    second = FakeCollector([_alert("2026-07-19T10:00:05+00:00")], "2026-07-19T10:00:05+00:00")
    monkeypatch.setattr(runtime, "get_collector", lambda v, c: second)
    await client.post(f"/api/v1/connectors/{cid}/poll", headers=auth)
    assert second.seen_cursor == "2026-07-19T10:00:01+00:00"  # resumed from the stored cursor


async def test_sweep_polls_enabled_only(client, monkeypatch):
    auth, tid = await _auth(client, "cr-sweep")
    on = (await client.post("/api/v1/connectors",
          json={**WAZUH_DRAFT, "name": "on"}, headers=auth)).json()["id"]
    off = (await client.post("/api/v1/connectors",
           json={**WAZUH_DRAFT, "name": "off", "enabled": False}, headers=auth)).json()["id"]

    monkeypatch.setattr(
        runtime, "get_collector",
        lambda v, c: FakeCollector([_alert("2026-07-19T10:00:01+00:00")], "2026-07-19T10:00:01Z"),
    )
    total = await runtime.sweep_once()
    assert total == 1  # only the enabled connector was polled

    async with tenant_session(uuid.UUID(tid)) as s:
        on_run = await s.scalar(select(Connector.last_run_at).where(Connector.id == on))
        off_run = await s.scalar(select(Connector.last_run_at).where(Connector.id == off))
    assert on_run is not None
    assert off_run is None  # disabled connector was never touched


async def test_poll_records_error_on_collector_failure(client, monkeypatch):
    auth, tid = await _auth(client, "cr-err")
    cid = (await client.post("/api/v1/connectors", json=WAZUH_DRAFT, headers=auth)).json()["id"]

    class Boom:
        source = "wazuh"

        async def collect(self, *a, **k):
            raise ConnectionError("indexer unreachable")

    monkeypatch.setattr(runtime, "get_collector", lambda v, c: Boom())
    r = await client.post(f"/api/v1/connectors/{cid}/poll", headers=auth)
    assert r.status_code == 200, r.text  # operational failure is not a 5xx
    body = r.json()
    assert body["status"] == "error"
    assert "unreachable" in body["last_error"]


async def test_crowdstrike_poll_normalizes_falcon_alert(client, monkeypatch):
    """The second vendor end-to-end: a Falcon alert pulled by the runtime is
    normalized by the crowdstrike normalizer and lands with its ATT&CK
    technique carried through — proving the Collector protocol generalizes."""
    auth, tid = await _auth(client, "cr-cs")
    r = await client.post("/api/v1/connectors", json=CROWDSTRIKE_DRAFT, headers=auth)
    assert r.status_code == 201, r.text
    cid = r.json()["id"]

    alert = _falcon_alert("2026-07-19T10:00:00Z")
    monkeypatch.setattr(
        runtime, "get_collector",
        lambda v, c: FakeCollector([alert], "2026-07-19T10:00:00Z", source="crowdstrike"),
    )
    r = await client.post(f"/api/v1/connectors/{cid}/poll", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["last_ingested"] == 1

    async with tenant_session(uuid.UUID(tid)) as s:
        events = (await s.scalars(select(NormalizedEvent))).all()
        assert len(events) == 1
        ev = events[0]
        assert ev.host_name == "WIN-01"
        assert ev.severity == 70
        assert ev.attributes["mitre_technique_ids"] == ["T1036"]  # ATT&CK carried through
        assert ev.attributes["process_image"] == "svch0st.exe"
