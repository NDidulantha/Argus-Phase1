"""Integration test setup: requires a real Postgres (docker compose up -d db).

Skips cleanly when no database is reachable, so unit tests still run
anywhere. In CI a pgvector Postgres service is always provided.
"""

import asyncio
import os

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DB_URL = os.environ.get(
    "ARGUS_DATABASE_URL", "postgresql+asyncpg://argus:argus@localhost:5432/argus_test"
)


def _db_available() -> bool:
    async def ping() -> bool:
        engine = create_async_engine(DB_URL)
        try:
            async with asyncio.timeout(3):
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False
        finally:
            await engine.dispose()

    return asyncio.run(ping())


@pytest.fixture(scope="session")
def migrated_db() -> None:
    if not _db_available():
        pytest.skip("integration tests need Postgres: docker compose up -d db")

    async def reset_schema() -> None:
        # Drop every table in public (discovered, not hardcoded — a fixed
        # list silently rots each time a migration adds a table). Extensions
        # like pgvector are preserved, unlike DROP SCHEMA CASCADE.
        engine = create_async_engine(DB_URL, isolation_level="AUTOCOMMIT")
        async with engine.connect() as conn:
            tables = (
                await conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
            ).scalars().all()
            if tables:
                joined = ", ".join(f'"{t}"' for t in tables)
                await conn.execute(text(f"DROP TABLE IF EXISTS {joined} CASCADE"))
        await engine.dispose()

    asyncio.run(reset_schema())

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", DB_URL)
    command.upgrade(cfg, "head")


@pytest.fixture(autouse=True)
async def _fresh_engine():
    """Dispose the shared engine after each test.

    pytest-asyncio gives every test its own event loop; an asyncpg pool
    created on one loop cannot be reused on another.
    """
    from argus.infrastructure.db.session import dispose_engine

    yield
    await dispose_engine()
