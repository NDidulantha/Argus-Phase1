"""Endpoint-level tests. These are unit tests: the database probe is
patched. Integration tests against a real Postgres container arrive with
the schema/migrations step."""

import argus.api.v1.endpoints.health as health_endpoint


async def test_liveness_returns_200(client):
    resp = await client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.json() == {"status": "alive"}


async def test_readiness_ok_when_db_up(client, monkeypatch):
    async def fake_check() -> bool:
        return True

    monkeypatch.setattr(health_endpoint, "check_database", fake_check)
    resp = await client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ready"


async def test_readiness_503_when_db_down(client, monkeypatch):
    async def fake_check() -> bool:
        return False

    monkeypatch.setattr(health_endpoint, "check_database", fake_check)
    resp = await client.get("/api/v1/health/ready")
    assert resp.status_code == 503
    assert resp.json()["status"] == "degraded"


async def test_request_id_header_is_returned(client):
    resp = await client.get("/api/v1/health/live", headers={"x-request-id": "trace-123"})
    assert resp.headers["x-request-id"] == "trace-123"
