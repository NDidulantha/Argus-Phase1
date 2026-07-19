#!/usr/bin/env python3
"""Re-run the deterministic ATT&CK classifier over a tenant's stored events.

Rules evolve faster than telemetry arrives. This backfills technique
mappings without re-replaying the dataset: wipe the tenant's rule-sourced
tags, re-classify every stored normalized event in batches, then rebuild
the open evidence objects. Vendor-sourced tags are never touched.

Usage:
  uv run python scripts/reclassify.py --tenant apt29v2
  uv run python scripts/reclassify.py --tenant apt29v2 --skip-correlate
  uv run python scripts/reclassify.py --tenant apt29v2 --correlate-only
"""

import argparse
import asyncio
import sys
from types import SimpleNamespace

from sqlalchemy import delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from argus.infrastructure.db.models import EventTechnique, NormalizedEvent, Tenant
from argus.infrastructure.db.session import admin_session, dispose_engine, tenant_session
from argus.services.correlation import correlate_tenant
from argus.services.mitre import extract_vendor_technique_ids
from argus.services.technique_rules import classify

BATCH = 10_000


async def run(slug: str, skip_correlate: bool, correlate_only: bool) -> int:
    async with admin_session() as s:
        tenant = await s.scalar(
            select(Tenant).where(or_(Tenant.slug == slug, Tenant.name == slug))
        )
        if tenant is None:
            print(f"error: no tenant with slug or name {slug!r}", file=sys.stderr)
            return 1
        tenant_id = tenant.id
    print(f"tenant: {tenant.name} ({tenant_id})")

    if correlate_only:
        async with tenant_session(tenant_id) as s:
            written = await correlate_tenant(s, tenant_id)
        print(f"correlation: {written} open evidence objects rebuilt")
        await dispose_engine()
        return 0

    async with tenant_session(tenant_id) as s:
        result = await s.execute(
            delete(EventTechnique).where(EventTechnique.mapping_source == "rules")
        )
        print(f"deleted {result.rowcount} rule-sourced tags")

    last_id, scanned, tagged = 0, 0, 0
    while True:
        async with tenant_session(tenant_id) as s:
            rows = (
                await s.execute(
                    select(
                        NormalizedEvent.id,
                        NormalizedEvent.event_time,
                        NormalizedEvent.category,
                        NormalizedEvent.action,
                        NormalizedEvent.attributes,
                    )
                    .where(NormalizedEvent.id > last_id)
                    .order_by(NormalizedEvent.id)
                    .limit(BATCH)
                )
            ).all()
            if not rows:
                break
            last_id = rows[-1].id
            scanned += len(rows)

            values = []
            for r in rows:
                event = SimpleNamespace(
                    category=r.category, action=r.action, attributes=r.attributes
                )
                if extract_vendor_technique_ids(event):
                    continue  # vendor tags exist from ingest and take precedence
                for m in classify(event):
                    values.append(
                        {
                            "tenant_id": tenant_id,
                            "normalized_event_id": r.id,
                            "technique_id": m.technique_id,
                            "event_time": r.event_time,
                            "mapping_source": "rules",
                            "confidence": m.confidence,
                        }
                    )
            if values:
                stmt = pg_insert(EventTechnique).values(values)
                await s.execute(stmt.on_conflict_do_nothing(constraint="uq_event_technique"))
                tagged += len(values)
        print(f"  scanned={scanned} tagged={tagged}", flush=True)

    print(f"done: {scanned} events scanned, {tagged} technique tags written")

    if not skip_correlate:
        async with tenant_session(tenant_id) as s:
            written = await correlate_tenant(s, tenant_id)
        print(f"correlation: {written} open evidence objects rebuilt")

    await dispose_engine()
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tenant", required=True, help="tenant slug or name")
    p.add_argument("--skip-correlate", action="store_true")
    p.add_argument("--correlate-only", action="store_true", help="rebuild evidence, no re-tag")
    args = p.parse_args()
    return asyncio.run(run(args.tenant, args.skip_correlate, args.correlate_only))


if __name__ == "__main__":
    raise SystemExit(main())
