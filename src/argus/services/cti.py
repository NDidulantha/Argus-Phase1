"""CTI service: cache-first, multi-provider indicator intelligence.

For an indicator, query every applicable CTI provider (cache-first, TTL'd),
returning cited findings. A provider error degrades to 'no result' — never
fails the lookup. Truthful 'not found' is a valid, valuable answer.
"""

import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.config import get_settings
from argus.cti.registry import get_cti_providers
from argus.domain.cti import CTIFinding
from argus.infrastructure.db.models import CTICache

log = structlog.get_logger()


def _finding_from_cache(row: CTICache) -> CTIFinding:
    return CTIFinding(**row.finding)


async def lookup_cti(
    session: AsyncSession, indicator_type: str, value: str
) -> list[CTIFinding]:
    ttl = timedelta(hours=get_settings().cti_cache_ttl_hours)
    now = datetime.now(UTC)
    findings: list[CTIFinding] = []

    for provider in get_cti_providers():
        if indicator_type not in provider.supported_types:
            continue

        cached = await session.scalar(
            select(CTICache).where(
                CTICache.provider == provider.provider,
                CTICache.indicator_type == indicator_type,
                CTICache.indicator_value == value,
            )
        )
        if cached is not None and cached.fetched_at > now - ttl:
            findings.append(_finding_from_cache(cached))
            continue

        try:
            finding = await provider.lookup(indicator_type, value)
        except Exception as exc:  # noqa: BLE001 - degrade, never fail
            log.warning("cti_provider_failed", provider=provider.provider,
                        indicator=value, error=str(exc)[:200])
            continue

        stmt = pg_insert(CTICache).values(
            provider=finding.provider,
            indicator_type=indicator_type,
            indicator_value=value,
            found=finding.found,
            finding=asdict(finding),
            fetched_at=now,
        ).on_conflict_do_update(
            constraint="uq_cti_indicator",
            set_={"found": finding.found, "finding": asdict(finding), "fetched_at": now},
        )
        await session.execute(stmt)
        findings.append(finding)

    return findings


async def lookup_cti_tenant(
    tenant_id: uuid.UUID, indicator_type: str, value: str
) -> list[CTIFinding]:
    # CTI cache is global; use an admin (non-tenant) session.
    from argus.infrastructure.db.session import admin_session

    async with admin_session() as s:
        return await lookup_cti(s, indicator_type, value)
