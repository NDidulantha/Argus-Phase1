"""Connector endpoints: configure SIEM/XDR data sources with no terminal
work (ui-design §4.11). Catalog -> wizard -> test -> save.

Credentials are write-only: accepted on create/update, stored, and never
serialized back out. The live connection test is real (it probes the
vendor endpoint); vendors without a shipped collector are listed as
planned and cannot be configured yet.
"""

import time
from datetime import UTC, datetime
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from argus.api.deps import CurrentUser, get_current_user
from argus.infrastructure.db.models import Connector
from argus.infrastructure.db.session import tenant_session

router = APIRouter(prefix="/connectors", tags=["connectors"])

# Mirrors the WazuhNormalizer mapping — shown in the wizard so the analyst
# sees exactly how vendor fields land in normalized events.
_WAZUH_MAPPING = {
    "timestamp": "event_time",
    "rule.groups[0]": "category",
    "rule.description": "action",
    "rule.level": "severity",
    "agent.name": "host_name",
    "data.dstuser / data.srcuser": "user_name",
    "data.srcip": "src_ip",
    "data.dstip": "dst_ip",
    "rule.mitre.id": "mitre_technique_ids",
}

CATALOG: list[dict[str, Any]] = [
    {
        "vendor": "wazuh",
        "name": "Wazuh",
        "description": "Pull alerts from the Wazuh Indexer (OpenSearch API).",
        "supported": True,
        "endpoint_hint": "https://indexer-host:9200",
        "credential_fields": ["username", "password"],
        "default_mapping": _WAZUH_MAPPING,
    },
    {
        "vendor": "cortex_xdr",
        "name": "Cortex XDR",
        "description": "Palo Alto Cortex XDR incidents and alerts.",
        "supported": False,
    },
    {
        "vendor": "crowdstrike",
        "name": "CrowdStrike Falcon",
        "description": "Falcon detections via the streaming API.",
        "supported": False,
    },
    {
        "vendor": "sentinel",
        "name": "Microsoft Sentinel",
        "description": "Sentinel incidents via the Azure Monitor API.",
        "supported": False,
    },
    {
        "vendor": "fortisiem",
        "name": "FortiSIEM",
        "description": "FortiSIEM incidents and CMDB context.",
        "supported": False,
    },
    {
        "vendor": "chronicle",
        "name": "Google Chronicle",
        "description": "Chronicle detections and UDM events.",
        "supported": False,
    },
    {
        "vendor": "qradar",
        "name": "IBM QRadar",
        "description": "QRadar offenses via the Ariel API.",
        "supported": False,
    },
]

_SUPPORTED = {c["vendor"] for c in CATALOG if c["supported"]}


async def probe_connector(
    vendor: str, endpoint_url: str, credentials: dict[str, Any], verify_tls: bool
) -> tuple[bool, str]:
    """Live connection test. Wazuh: hit the indexer's _cluster/health."""
    if vendor != "wazuh":
        return False, f"no collector shipped for vendor '{vendor}' yet"
    url = endpoint_url.rstrip("/") + "/_cluster/health"
    auth = (credentials.get("username", ""), credentials.get("password", ""))
    try:
        async with httpx.AsyncClient(verify=verify_tls, timeout=6.0) as client:
            resp = await client.get(url, auth=auth)
    except httpx.HTTPError as e:
        return False, f"could not reach the indexer: {e.__class__.__name__}: {e}"
    if resp.status_code == 401:
        return False, "the indexer rejected those credentials (401)"
    if resp.status_code != 200:
        return False, f"the indexer answered HTTP {resp.status_code}"
    try:
        body = resp.json()
        return True, f"cluster '{body.get('cluster_name', '?')}' is {body.get('status', '?')}"
    except ValueError:
        return False, "the endpoint answered, but not like an OpenSearch indexer"


class ConnectorOut(BaseModel):
    id: int
    vendor: str
    name: str
    endpoint_url: str
    verify_tls: bool
    field_mapping: dict[str, Any]
    status: str
    last_checked_at: datetime | None
    last_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}  # credentials intentionally absent


class ConnectorListOut(BaseModel):
    items: list[ConnectorOut]


class ConnectorCreateIn(BaseModel):
    vendor: str
    name: str = Field(min_length=1, max_length=200)
    endpoint_url: str = Field(min_length=1, max_length=500)
    credentials: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True
    field_mapping: dict[str, str] | None = None


class ConnectorUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    endpoint_url: str | None = Field(default=None, min_length=1, max_length=500)
    credentials: dict[str, str] | None = None
    verify_tls: bool | None = None
    field_mapping: dict[str, str] | None = None


class TestDraftIn(BaseModel):
    vendor: str
    endpoint_url: str = Field(min_length=1, max_length=500)
    credentials: dict[str, str] = Field(default_factory=dict)
    verify_tls: bool = True


class TestResultOut(BaseModel):
    ok: bool
    detail: str
    latency_ms: int


@router.get("/catalog")
async def connector_catalog(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[dict[str, Any]]:
    return CATALOG


@router.get("", response_model=ConnectorListOut)
async def list_connectors(
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ConnectorListOut:
    async with tenant_session(current.tenant_id) as s:
        rows = (await s.scalars(select(Connector).order_by(Connector.created_at))).all()
    return ConnectorListOut(items=[ConnectorOut.model_validate(r) for r in rows])


@router.post("/test", response_model=TestResultOut)
async def test_draft(
    body: TestDraftIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> TestResultOut:
    """Stateless wizard test: probe before anything is saved."""
    t0 = time.monotonic()
    ok, detail = await probe_connector(
        body.vendor, body.endpoint_url, body.credentials, body.verify_tls
    )
    return TestResultOut(ok=ok, detail=detail, latency_ms=int((time.monotonic() - t0) * 1000))


@router.post("", response_model=ConnectorOut, status_code=201)
async def create_connector(
    body: ConnectorCreateIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ConnectorOut:
    if body.vendor not in _SUPPORTED:
        raise HTTPException(400, f"vendor '{body.vendor}' is not supported yet")
    default_mapping = next(
        (c.get("default_mapping", {}) for c in CATALOG if c["vendor"] == body.vendor), {}
    )
    async with tenant_session(current.tenant_id) as s:
        connector = Connector(
            tenant_id=current.tenant_id,
            vendor=body.vendor,
            name=body.name,
            endpoint_url=body.endpoint_url,
            credentials=body.credentials,
            verify_tls=body.verify_tls,
            field_mapping=body.field_mapping or default_mapping,
        )
        s.add(connector)
        await s.flush()
        return ConnectorOut.model_validate(connector)


async def _get_connector(s, connector_id: int) -> Connector:
    connector = await s.get(Connector, connector_id)
    if connector is None:
        raise HTTPException(404, "Connector not found")
    return connector


@router.post("/{connector_id}/test", response_model=ConnectorOut)
async def test_connector(
    connector_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ConnectorOut:
    """Probe the stored config and persist the resulting health status."""
    async with tenant_session(current.tenant_id) as s:
        connector = await _get_connector(s, connector_id)
        ok, detail = await probe_connector(
            connector.vendor,
            connector.endpoint_url,
            connector.credentials,
            connector.verify_tls,
        )
        connector.status = "healthy" if ok else "error"
        connector.last_checked_at = datetime.now(UTC)
        connector.last_error = None if ok else detail
        connector.updated_at = datetime.now(UTC)
        await s.flush()
        return ConnectorOut.model_validate(connector)


@router.patch("/{connector_id}", response_model=ConnectorOut)
async def update_connector(
    connector_id: int,
    body: ConnectorUpdateIn,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> ConnectorOut:
    async with tenant_session(current.tenant_id) as s:
        connector = await _get_connector(s, connector_id)
        for field in ("name", "endpoint_url", "credentials", "verify_tls", "field_mapping"):
            value = getattr(body, field)
            if value is not None:
                setattr(connector, field, value)
        connector.updated_at = datetime.now(UTC)
        await s.flush()
        return ConnectorOut.model_validate(connector)


@router.delete("/{connector_id}", status_code=204)
async def delete_connector(
    connector_id: int,
    current: Annotated[CurrentUser, Depends(get_current_user)],
) -> None:
    async with tenant_session(current.tenant_id) as s:
        connector = await _get_connector(s, connector_id)
        await s.delete(connector)
