import os

# Tests must NEVER touch the dev database: running pytest once wiped the
# dev tenants table (and, via CASCADE, all ingested lab events). Point the
# whole suite at a dedicated database unless the environment (e.g. CI)
# explicitly says otherwise.
os.environ.setdefault(
    "ARGUS_DATABASE_URL", "postgresql+asyncpg://argus:argus@localhost:5432/argus_test"
)

import pytest
from httpx import ASGITransport, AsyncClient

from argus.core.config import get_settings
from argus.main import create_app


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Ensure each test resolves settings fresh from the environment."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def client():
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
