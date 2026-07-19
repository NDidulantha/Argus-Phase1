"""CTI lookup: cache-first, cited findings, with a fake provider."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

import argus.services.cti as cti_service
from argus.domain.cti import CTIFinding
from argus.infrastructure.db.models import CTICache, Tenant
from argus.infrastructure.db.session import admin_session
from argus.main import create_app

ADMIN = {"X-Admin-Key": "dev-admin-key-change-me"}


class FakeCTI:
    provider = "faketi"
    supported_types = frozenset({"ip"})
    calls = 0

    async def lookup(self, indicator_type, value):
        FakeCTI.calls += 1
        return CTIFinding(
            provider="faketi", indicator_type=indicator_type, indicator_value=value,
            found=True, malware=["Emotet"], threat_actors=["TA542"],
            reference_url="https://example.test/ioc/1",
            summary="Known Emotet C2.",
        )


@pytest.fixture
async def client(migrated_db, monkeypatch):
    FakeCTI.calls = 0
    monkeypatch.setattr(cti_service, "get_cti_providers", lambda: [FakeCTI()])
    async with admin_session() as s:
        await s.execute(delete(Tenant))
        await s.execute(delete(CTICache))
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c


async def _auth(client) -> dict:
    r = await client.post("/api/v1/admin/tenants", json={"name": "C", "slug": "cti"}, headers=ADMIN)
    tid = r.json()["id"]
    await client.post(f"/api/v1/admin/tenants/{tid}/users",
        json={"email": "a@cti.x", "password": "a-strong-password!"}, headers=ADMIN)
    r = await client.post("/api/v1/auth/login",
        json={"tenant_slug": "cti", "email": "a@cti.x", "password": "a-strong-password!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_cti_lookup_returns_cited_finding_and_caches(client):
    auth = await _auth(client)
    body = {"indicator_type": "ip", "value": "5.6.7.8"}
    r1 = await client.post("/api/v1/cti/lookup", json=body, headers=auth)
    assert r1.status_code == 200, r1.text
    d = r1.json()
    assert d["any_found"] is True
    f = d["findings"][0]
    assert f["malware"] == ["Emotet"]
    assert f["reference_url"] == "https://example.test/ioc/1"  # citation present
    assert FakeCTI.calls == 1

    r2 = await client.post("/api/v1/cti/lookup", json=body, headers=auth)
    assert r2.json()["any_found"] is True
    assert FakeCTI.calls == 1  # served from cache


async def test_invalid_cve_rejected(client):
    auth = await _auth(client)
    r = await client.post("/api/v1/cti/lookup",
        json={"indicator_type": "cve", "value": "not-a-cve"}, headers=auth)
    assert r.status_code == 422


def _sysmon_with_ip(minute: int) -> dict:
    return {"@timestamp": f"2020-08-07T14:{minute:02d}:00Z", "EventID": 3,
            "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "wks-cti",
            "Message": "Network connection detected", "SourceIp": "10.0.0.5",
            "DestinationIp": "5.6.7.8"}


async def test_lookup_reports_local_sightings(client):
    auth = await _auth(client)
    r = await client.post("/api/v1/events", json={
        "source": "securitydatasets",
        "events": [_sysmon_with_ip(0), _sysmon_with_ip(5)],
    }, headers=auth)
    assert r.json()["normalized"] == 2

    r = await client.post("/api/v1/cti/lookup",
        json={"indicator_type": "ip", "value": "5.6.7.8"}, headers=auth)
    s = r.json()["sightings"]
    assert s is not None
    assert s["events"] == 2
    assert s["first_seen"] and s["last_seen"]

    # an indicator the tenant never saw carries no sightings block
    r = await client.post("/api/v1/cti/lookup",
        json={"indicator_type": "ip", "value": "9.9.9.9"}, headers=auth)
    assert r.json()["sightings"] is None


async def test_hunt_sweep_flags_stored_indicators(client):
    auth = await _auth(client)
    await client.post("/api/v1/events", json={
        "source": "securitydatasets",
        "events": [_sysmon_with_ip(0), _sysmon_with_ip(5), _sysmon_with_ip(10)],
    }, headers=auth)

    r = await client.post("/api/v1/cti/hunt", headers=auth)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["indicators_checked"] >= 1  # 5.6.7.8 (public); 10.0.0.5 excluded
    hit = next(h for h in d["hits"] if h["value"] == "5.6.7.8")
    assert hit["indicator_type"] == "ip"
    assert hit["local_events"] == 3
    assert hit["findings"][0]["provider"] == "faketi"

    # private IPs never burn provider quota
    assert all(h["value"] != "10.0.0.5" for h in d["hits"])


async def test_hunt_persists_findings_and_upserts(client):
    """A hunt writes durable leads; a repeat sweep updates, never duplicates."""
    auth = await _auth(client)
    await client.post("/api/v1/events", json={
        "source": "securitydatasets",
        "events": [_sysmon_with_ip(0), _sysmon_with_ip(5)],
    }, headers=auth)

    # findings list starts empty
    r = await client.get("/api/v1/cti/hunt/findings", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["findings"] == []
    assert r.json()["last_swept"] is None

    await client.post("/api/v1/cti/hunt", headers=auth)
    r = await client.get("/api/v1/cti/hunt/findings", headers=auth)
    d = r.json()
    assert len(d["findings"]) == 1
    f = d["findings"][0]
    assert f["value"] == "5.6.7.8"
    assert f["provider"] == "faketi"
    assert f["local_events"] == 2
    assert f["finding"]["malware"] == ["Emotet"]
    assert d["last_swept"] is not None
    first_seen = f["first_seen"]

    # a third sighting then a re-hunt: same row updated, not a new one
    await client.post("/api/v1/events", json={
        "source": "securitydatasets", "events": [_sysmon_with_ip(10)],
    }, headers=auth)
    await client.post("/api/v1/cti/hunt", headers=auth)
    r = await client.get("/api/v1/cti/hunt/findings", headers=auth)
    d = r.json()
    assert len(d["findings"]) == 1  # upsert, not duplicate
    assert d["findings"][0]["local_events"] == 3  # volume bumped
    assert d["findings"][0]["first_seen"] == first_seen  # original discovery kept


async def test_autonomous_sweep_persists_across_tenants(client):
    """auto_hunt.sweep_once hunts every active tenant and stores what it finds
    — the 'always on' path, with no analyst clicking anything."""
    from argus.services import auto_hunt

    auth = await _auth(client)
    await client.post("/api/v1/events", json={
        "source": "securitydatasets",
        "events": [_sysmon_with_ip(0), _sysmon_with_ip(5)],
    }, headers=auth)

    written = await auto_hunt.sweep_once()
    assert written >= 1

    r = await client.get("/api/v1/cti/hunt/findings", headers=auth)
    d = r.json()
    assert any(f["value"] == "5.6.7.8" for f in d["findings"])
