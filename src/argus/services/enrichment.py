"""Enrichment service: cache-first indicator lookups.

Order of operations per provider: fresh cache row -> return it (zero API
cost); miss or stale -> call provider, upsert cache, return. A provider
error yields no result rather than failing the lookup — intel providers
rate-limit and outage constantly; ARGUS degrades gracefully.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from argus.core.config import get_settings
from argus.enrichers.registry import get_enrichers
from argus.infrastructure.db.models import EnrichmentCache

log = structlog.get_logger()


@dataclass(frozen=True)
class LookupEntry:
    provider: str
    score: int | None
    verdict: str
    cached: bool
    fetched_at: datetime


async def lookup_indicator(
    session: AsyncSession, indicator_type: str, value: str
) -> list[LookupEntry]:
    settings = get_settings()
    ttl = timedelta(hours=settings.enrichment_cache_ttl_hours)
    now = datetime.now(UTC)
    entries: list[LookupEntry] = []

    for enricher in get_enrichers():
        if indicator_type not in enricher.supported_types:
            continue

        cached = await session.scalar(
            select(EnrichmentCache).where(
                EnrichmentCache.provider == enricher.provider,
                EnrichmentCache.indicator_type == indicator_type,
                EnrichmentCache.indicator_value == value,
            )
        )
        if cached is not None and cached.fetched_at > now - ttl:
            entries.append(
                LookupEntry(
                    provider=enricher.provider,
                    score=cached.score,
                    verdict=cached.verdict,
                    cached=True,
                    fetched_at=cached.fetched_at,
                )
            )
            continue

        try:
            result = await enricher.enrich(indicator_type, value)
        except Exception as exc:  # noqa: BLE001 - degrade, don't fail
            log.warning(
                "enrichment_provider_failed",
                provider=enricher.provider,
                indicator=value,
                error=str(exc)[:200],
            )
            continue

        stmt = pg_insert(EnrichmentCache).values(
            provider=result.provider,
            indicator_type=result.indicator_type,
            indicator_value=result.indicator_value,
            score=result.score,
            verdict=result.verdict,
            raw=result.raw,
            fetched_at=now,
        )
        stmt = stmt.on_conflict_do_update(
            constraint="uq_enrichment_indicator",
            set_={
                "score": stmt.excluded.score,
                "verdict": stmt.excluded.verdict,
                "raw": stmt.excluded.raw,
                "fetched_at": stmt.excluded.fetched_at,
            },
        )
        await session.execute(stmt)
        entries.append(
            LookupEntry(
                provider=result.provider,
                score=result.score,
                verdict=result.verdict,
                cached=False,
                fetched_at=now,
            )
        )

    return entries
