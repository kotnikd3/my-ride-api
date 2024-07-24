import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope='function')
def test_client():
    app.dependency_overrides = {}

    with TestClient(app) as c:
        yield c
