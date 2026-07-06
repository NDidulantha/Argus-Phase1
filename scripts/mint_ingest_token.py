"""Mint a long-lived ingest token for a machine connector (lab/dev use).

Usage:
    uv run python scripts/mint_ingest_token.py --tenant-slug home-lab \
        --email wazuh-connector@home-lab.local --days 90

Interim solution: this is a normal user JWT with a long expiry. The proper
phase for connector auth introduces dedicated per-connector API keys with
revocation; tracked as future work (see ADR 0006 note in events endpoint).
"""

import argparse
import asyncio
import sys

from sqlalchemy import select

from argus.core.security import create_access_token
from argus.infrastructure.db.models import Tenant, User
from argus.infrastructure.db.session import admin_session, dispose_engine, tenant_session


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--tenant-slug", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--days", type=int, default=90)
    args = p.parse_args()

    async with admin_session() as s:
        tenant = await s.scalar(select(Tenant).where(Tenant.slug == args.tenant_slug))
    if tenant is None:
        print(f"error: no tenant with slug '{args.tenant_slug}'", file=sys.stderr)
        return 1

    async with tenant_session(tenant.id) as s:
        user = await s.scalar(select(User).where(User.email == args.email.lower()))
    if user is None:
        print(f"error: no user '{args.email}' in tenant '{args.tenant_slug}'", file=sys.stderr)
        return 1

    token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role,
        expires_minutes=args.days * 24 * 60,
    )
    print(token)
    await dispose_engine()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
