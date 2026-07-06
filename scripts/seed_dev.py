"""Idempotent dev seed: ensure a tenant + connector user exist and print a
90-day ingest token. Safe to run repeatedly — recovers instantly after a
volume wipe. NOT for production (uses dev conventions).

Usage:
  uv run python scripts/seed_dev.py                      # home-lab tenant
  uv run python scripts/seed_dev.py --slug lab-replay
"""

import argparse
import asyncio
import re
import secrets
from pathlib import Path

from sqlalchemy import select

from argus.core.security import create_access_token, hash_password
from argus.infrastructure.db.models import Tenant, User
from argus.infrastructure.db.session import admin_session, dispose_engine, tenant_session


def _write_env_token(token: str) -> None:
    """Upsert ARGUS_TOKEN in .env so there is ONE source of truth. Avoids
    the classic stale-token trap where .env and the live tenant diverge."""
    env = Path(".env")
    lines = env.read_text().splitlines() if env.exists() else []
    lines = [ln for ln in lines if not re.match(r"\s*ARGUS_TOKEN\s*=", ln)]
    lines.append(f"ARGUS_TOKEN={token}")
    env.write_text("\n".join(lines) + "\n")


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--slug", default="home-lab")
    p.add_argument("--name", default=None)
    p.add_argument("--days", type=int, default=90)
    args = p.parse_args()
    name = args.name or args.slug.replace("-", " ").title()
    email = f"connector@{args.slug}.local"

    async with admin_session() as s:
        tenant = await s.scalar(select(Tenant).where(Tenant.slug == args.slug))
        if tenant is None:
            tenant = Tenant(name=name, slug=args.slug)
            s.add(tenant)
            await s.flush()
        tenant_id = tenant.id

    async with tenant_session(tenant_id) as s:
        user = await s.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                tenant_id=tenant_id,
                email=email,
                password_hash=hash_password(secrets.token_urlsafe(24)),
                role="analyst",
            )
            s.add(user)
            await s.flush()
        user_id, role = user.id, user.role

    token = create_access_token(
        user_id=user_id, tenant_id=tenant_id, role=role, expires_minutes=args.days * 24 * 60
    )
    await dispose_engine()

    _write_env_token(token)
    print(f"tenant : {args.slug} ({tenant_id})")
    print(f"user   : {email}")
    print("token  : written to .env as ARGUS_TOKEN")
    print()
    print(">>> Now run this in EACH open terminal to load it:")
    print(">>>   set -a; source .env; set +a")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
