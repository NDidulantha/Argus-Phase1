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
