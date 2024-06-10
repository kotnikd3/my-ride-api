import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
from api.infrastructure.controllers import app, COOKIE_NAME
from api.services.exceptions import RefreshTokenExpiredError, InvalidTokenError
from api.infrastructure.authentication import KeycloakTokenValidator
from unittest import TestCase


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware
from httpx import AsyncClient
from unittest.mock import patch

from api.infrastructure.controllers import app  # Adjust import according to your app's entry point

# client = TestClient(app)
from base64 import b64encode

from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner
import json
client = TestClient(app)
from starlette.testclient import TestClient

a = TestClient(app)
@pytest.fixture
def session():
    # Setting up a sample session for testing
    return {
        "my-ride": {
            "access_token": "valid-access-token",
            "refresh_token": "valid-refresh-token",
        }
    }

@pytest.fixture
def setup_app(session):
    app.add_middleware(
        SessionMiddleware,
        secret_key="foo",
        session_cookie="my-ride",
        https_only=True,
        max_age=1800,
    )
    with client as c:
        with c.session_transaction() as s:
            s.update(session)
    return client

def test_login_redirect():
    response = setup_app.get("/")
    assert response.status_code == 307
    assert "location" in response.headers

#
# def test_logout(setup_app):
#     response = client.get("/login", cookies={COOKIE_NAME: create_session_cookie({'some': 'state'})})
#     assert response.status_code == 302
#     assert "location" in response.headers
#
# @pytest.fixture
# def session():
#     # Setting up a sample session for testing
#     return {
#         "my-ride": {
#             "access_token": "valid-access-token",
#             "refresh_token": "valid-refresh-token",
#         }
#     }
#
# @pytest.fixture
# def setup_app(session):
#     app.add_middleware(
#         SessionMiddleware,
#         secret_key="SL0m0IqlK0O8",
#         session_cookie="my-ride",
#         https_only=True,
#         max_age=1800,
#     )
#     with client as c:
#         with c.session_transaction() as s:
#             s.update(session)
#     return client
#
# def test_login_redirect():
#     with client as c:
#         with c.session_transaction() as s:
#         response = client.get("/")
#     assert response.status_code == 200
#     assert "location" in response.headers
#
# def test_authorize():
#     with patch('api.infrastructure.authentication.KeycloakTokenValidator.get_tokens') as mock_get_tokens:
#         mock_get_tokens.return_value = {
#             'access_token': 'new-access-token',
#             'refresh_token': 'new-refresh-token'
#         }
#         response = client.get("/authorize?code=test-code")
#         assert response.status_code == 302
#         assert "location" in response.headers
#         assert response.headers["location"].endswith("/")
#
# def test_logout(setup_app):
#     response = setup_app.get("/logout")
#     assert response.status_code == 302
#     assert "location" in response.headers

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient

class MockSessionMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, http_request: Request, call_next: RequestResponseEndpoint) -> Response:
        http_request.scope['session'] = {'user': {'username':  'testScarlette'}}
        return await call_next(http_request)

app.add_middleware(MockSessionMiddleware)
from starlette.middleware import Middleware

class TestController(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cookie_name = 'test_cookie'

    @classmethod
    def tearDownClass(cls) -> None:
        pass
    def test_index_without_session(self):
        client = TestClient(app, cookies={"key": "secret"})
        response = client.get("/")
        self.assertEqual(200, response.status_code)
        self.assertIn('My ride', response.text)
        # assert response.json() == {"username": "secret"}

    def test_index_with_session(self):
        # client = TestClient(app)
        # client.cookies[COOKIE_NAME] = 'something'
        response = client.get("/", headers={'set-cookie': 'my-session=dafer'})
        self.assertEqual(200, response.status_code)
        self.assertIn('secret', response.text)
        # assert response.json() == {"username": "secret"}



# Mock KeycloakTokenValidator for testing
class MockKeycloakTokenValidator:
    def auth_url(self, redirect_uri, scope):
        return "http://mockauth.url"

    def get_tokens(self, code, redirect_uri):
        return {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
        }

    def authenticate_token(self, token_string):
        if token_string != "mock_access_token":
            raise InvalidTokenError("Invalid token")

    def fetch_new_tokens(self, refresh_token):
        if refresh_token == "mock_refresh_token":
            return {
                'access_token': 'new_mock_access_token',
                'refresh_token': 'new_mock_refresh_token',
            }
        raise RefreshTokenExpiredError("Refresh token expired")

    def logout(self, refresh_token):
        pass

app.dependency_overrides[KeycloakTokenValidator] = MockKeycloakTokenValidator

@pytest.fixture
def set_up():
    # Setup code for each test
    yield
    # Teardown code for each test
    app.dependency_overrides = {}

def test_login():
    response = client.get("/login")
    assert response.status_code == 200
    assert response.headers["location"] == "http://mockauth.url"
    assert response.is_redirect

def test_authorize():
    response = client.get("/authorize?code=mock_code")
    assert response.status_code == 302
    assert response.headers["location"] == client.base_url + "/"

    cookies = response.cookies
    assert COOKIE_NAME in cookies
    assert cookies[COOKIE_NAME] == {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }

def test_index_without_session():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"data": {}}

def test_index_with_session():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"data": {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }}

def test_logout():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/logout")
    assert response.status_code == 302
    assert response.headers["location"] == client.base_url + "/"

    cookies = response.cookies
    assert COOKIE_NAME not in cookies

def test_protected_endpoint_without_session():
    response = client.get("/rides")
    assert response.status_code == 401
    assert response.json() == {"detail": "Token is not valid"}

def test_protected_endpoint_with_session():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    })

    response = client.get("/rides")
    assert response.status_code == 200
    assert response.json() == {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token'
    }

def test_session_expiration():
    client.cookies.set(COOKIE_NAME, {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token',
        'expires': (datetime.now() - timedelta(seconds=1)).strftime('%Y-%m-%d %H:%M:%S.%f')
    })

    response = client.get("/rides")
    assert response.status_code == 401
    assert response.json() == {"detail": "Session expired"}