from typing import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient

from api.main import app


@pytest.fixture(scope='function')
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    app.dependency_overrides = {}
    transport = ASGITransport(app=app)

    async with AsyncClient(
        transport=transport, base_url='http://testserver'
    ) as client:
        yield client
